#!/usr/bin/env python3
"""Heartbeat monitor for processes that never exit.

job_watchdog.py supervises jobs that start, do work and finish. A long-running
service is a different failure mode entirely: the process is alive, the
supervisor shows green, and it has not done any useful work since Tuesday.
A revoked API token, a dependency that started returning empty pages, a
consumer stuck on a socket that will never time out - none of these kill the
process, and none of them show up in `systemctl status` or the Task Scheduler.

The fix is for the service to prove it is working, not merely running. Three
lines inside the loop, after the part that must succeed:

    import deadman
    ...
    deadman.beat("heartbeat/importer.txt")   # only on a successful cycle

and then this script, on a timer, checks that the file is still fresh.

    deadman.py                      # check every service in deadman.json
    deadman.py --report             # show status, send nothing
    deadman.py --beat FILE          # write a heartbeat (for shell scripts)
    deadman.py --test               # self-test

deadman.json:

    {"watch": [
       {"name": "importer",  "file": "heartbeat/importer.txt", "max_age_min": 15},
       {"name": "poller",    "file": "heartbeat/poller.txt",   "max_age_min": 5}
    ]}

Alert routing is in notify.py.

Placement matters more than the code: put beat() after the work, never at the
top of the loop. A heartbeat written before the work only proves the loop is
spinning, which is exactly the thing you already knew.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import notify

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = Path("deadman.json")
STATE = Path.home() / ".local/state/job-watchdog/deadman-state.json"

OK, STALE, MISSING, ILLEGIBLE = "ok", "stale", "missing", "illegible"

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# A heartbeat holds one timestamp and nothing else, so it stays group- and
# world-readable on purpose: the checker often runs as a different account
# from the service that writes it.
BEAT_MODE = 0o644
# A timestamp is about 19 bytes. Reading more than this means the path is
# pointing at something that is not a heartbeat, and a config typo should not
# be able to pull a multi-gigabyte file into memory.
BEAT_MAX_BYTES = 128


def beat(path: str | Path) -> None:
    """Record a successful cycle. Call this after the work, not before."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # O_NOFOLLOW: a service writing its heartbeat may well be running as root
    # or SYSTEM. If anyone can plant a symlink in the heartbeat directory,
    # following it would let them truncate a file of their choosing with those
    # privileges.
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | NOFOLLOW,
                 BEAT_MODE)
    with os.fdopen(fd, "w") as fh:
        fh.write(datetime.now().isoformat(timespec="seconds"))


def age_minutes(stamp: str, now: datetime) -> float | None:
    """Minutes since the last beat, or None if the file is not a timestamp."""
    try:
        return (now - datetime.fromisoformat(stamp.strip())).total_seconds() / 60
    except (ValueError, AttributeError, TypeError):
        return None


def check(entry: dict, now: datetime, base: Path = HERE) -> tuple[str, str]:
    """(status, human-readable detail).

    'missing' and 'illegible' are kept distinct from 'stale' on purpose: they
    mean different things when you are the one woken up. Stale is a service
    that stopped working. Missing is a service that never started, or a path
    that is wrong - usually a config mistake, not an outage.
    """
    path = Path(entry["file"])
    if not path.is_absolute():
        path = base / path
    if not path.exists():
        return MISSING, f"no heartbeat at {path}"
    try:
        with path.open("rb") as fh:
            raw = fh.read(BEAT_MAX_BYTES)
    except OSError as exc:
        return MISSING, f"cannot read heartbeat at {path}: {exc}"
    age = age_minutes(raw.decode("utf-8", "replace"), now)
    if age is None:
        return ILLEGIBLE, f"heartbeat at {path} is not a timestamp"
    limit = float(entry.get("max_age_min", 15))
    if age > limit:
        return STALE, f"silent for {age:.0f} min (limit {limit:.0f})"
    return OK, f"alive, last beat {age:.1f} min ago"


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    # Owner-only, like job_watchdog's: the file names the services running on
    # this machine, which is reconnaissance you should not hand out for free.
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        # 0o700 is owner-only; semgrep's suggested 0o644 would be looser.
        os.chmod(STATE.parent, 0o700)  # nosemgrep: insecure-file-permissions
    except OSError:
        pass
    try:
        fd = os.open(str(STATE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(state))
    except OSError as exc:
        print(f"deadman: could not save state: {exc}", file=sys.stderr)


def self_test() -> None:
    import tempfile

    now = datetime(2026, 7, 25, 12, 0)

    assert age_minutes((now - timedelta(minutes=5)).isoformat(), now) == 5
    assert age_minutes("not a date", now) is None
    assert age_minutes("", now) is None

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        hb = base / "svc.txt"
        entry = {"file": "svc.txt", "max_age_min": 15}

        assert check(entry, now, base)[0] == MISSING

        hb.write_text((now - timedelta(minutes=1)).isoformat())
        assert check(entry, now, base)[0] == OK

        # exactly at the limit is still alive; past it is not
        hb.write_text((now - timedelta(minutes=15)).isoformat())
        assert check(entry, now, base)[0] == OK
        hb.write_text((now - timedelta(minutes=16)).isoformat())
        assert check(entry, now, base)[0] == STALE

        hb.write_text("garbage")
        assert check(entry, now, base)[0] == ILLEGIBLE

        # beat() creates missing parent directories and writes a readable stamp
        nested = base / "deep" / "dir" / "svc.txt"
        beat(nested)
        fresh = age_minutes(nested.read_text(), datetime.now())
        assert fresh is not None and fresh < 1
        beat(nested)                      # overwriting an existing beat works

        # a symlink planted where the heartbeat goes must be refused: the
        # service writing it may be running as root or SYSTEM
        if os.name == "posix":
            victim = base / "victim"
            victim.write_text("original")
            bait = base / "bait.txt"
            os.symlink(victim, bait)
            try:
                beat(bait)
            except OSError:
                pass
            assert victim.read_text() == "original", "beat() followed a symlink"

        # a path pointing at something enormous must not be slurped into memory
        huge = base / "huge.txt"
        huge.write_bytes(b"0" * 5_000_000)
        status, _ = check({"file": "huge.txt", "max_age_min": 1}, now, base)
        assert status == ILLEGIBLE, status

        # a hostile service name must reach Telegram escaped, or the API
        # rejects the message and the alert is silently lost
        hostile = {"name": "<b>svc</b>", "file": "nope.txt", "max_age_min": 1}
        _, why = check(hostile, now, base)
        assert "<" not in notify.esc(f"{hostile['name']}{why}")

    print("OK - deadman.py")


def main() -> int:
    argv = sys.argv[1:]
    if "--test" in argv:
        self_test()
        return 0
    if "--beat" in argv:
        beat(argv[argv.index("--beat") + 1])
        return 0

    report_only = "--report" in argv
    cfg_path = Path(argv[argv.index("--config") + 1]) if "--config" in argv \
        else DEFAULT_CONFIG
    if not cfg_path.exists():
        print(f"missing config: {cfg_path}", file=sys.stderr)
        return 2

    cfg = json.loads(cfg_path.read_text())
    prev = load_state()
    now = datetime.now()
    state, broken = {}, 0

    for entry in cfg.get("watch", []):
        name = entry["name"]
        status, detail = check(entry, now, cfg_path.resolve().parent)
        state[name] = status
        print(f"{status:<10} {name:<20} {detail}")
        if status != OK:
            broken += 1
        if report_only:
            continue
        # Same rule as job_watchdog: speak on change, not on every tick. A
        # service that dies at 3am must not send 40 messages before morning.
        # Plain text in, encoded per channel by notify.send(): the name comes
        # from a config file and the detail contains a filesystem path, so
        # neither can be assumed safe for a markup-parsing channel.
        if status != OK and prev.get(name) != status:
            notify.send(f"{name} is not responding", detail)
        elif status == OK and prev.get(name) not in (None, OK):
            notify.send(f"OK - {name} is alive again")

    if not report_only:
        save_state(state)
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
