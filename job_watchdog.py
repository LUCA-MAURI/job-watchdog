#!/usr/bin/env python3
"""Supervise a scheduled job: retries, timeout, empty-output detection, alerts.

The failure that costs you the most is not the job that crashes. A crash has
an exit code, and cron or launchd or the Task Scheduler will show it. The
expensive one is the job that exits 0 and produces nothing, because an
upstream feed went dead six weeks ago and the parser dutifully returned an
empty list. Every dashboard stays green. Nobody finds out until someone asks
why a report has been blank since March.

I lost two data pipelines that way: an RSS aggregator whose provider quietly
retired the feed, and a scraper that started getting 403 and returned []
instead of raising. Both "succeeded" every single run.

So this wrapper treats three things as failure:

    exit code != 0        the obvious one
    timeout               a job that hangs forever is not a job that is running
    empty stdout          success with no output, unless you pass --allow-empty

Nothing changes inside the job. You put the wrapper in front of the command:

    job_watchdog.py daily-import -- python3 import.py
    job_watchdog.py daily-import --retries 3 --timeout 600 -- ./import.sh
    job_watchdog.py health --allow-empty -- ./check.sh

    job_watchdog.py --report      last outcome of every supervised job
    job_watchdog.py --test        self-test, no network, no side effects

Alert routing is in notify.py: Telegram, webhook, or stderr. See its docstring.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import notify

STATE_DIR = Path.home() / ".local/state/job-watchdog"
RUNS = STATE_DIR / "runs.json"
MAX_LOG_BYTES = 1_000_000
TAIL_CHARS = 500
REMIND_EVERY = 12
STREAM_CHUNK = 64 * 1024
# How much of the start of stdout is inspected to decide "is this empty".
# A job that emits more than this is not empty by any useful definition.
EMPTY_PROBE = 8192

# The state file records the tail of a failing job's output, which can contain
# anything the job printed - a connection string, a token in a stack trace. It
# is chmod 600 for the same reason ~/.ssh is: the machine may have other users.
DIR_MODE = 0o700
FILE_MODE = 0o600

# Never follow a symlink when creating a state file. Without this, anyone who
# can write into the state directory - including on a machine where an older
# version left it 0755 - can point runs.json at a file of their choosing and
# have this process overwrite it. Absent on Windows, where it is not needed.
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _state_dir() -> Path:
    """Create the state directory owner-only, and keep it that way."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        # semgrep's rule cannot resolve the constant and suggests 0o644
        # as 'a good default'. DIR_MODE is 0o700 - owner only - which is
        # stricter than what it recommends, not looser.
        os.chmod(STATE_DIR, DIR_MODE)  # nosemgrep: insecure-file-permissions
    except OSError:
        pass          # a read-only or foreign filesystem must not stop the run
    return STATE_DIR


def _write_private(path: Path, text: str) -> None:
    """Write a file that only the owner can read.

    Creating the file and then chmod-ing it leaves a window in which the
    default mode applies, so the descriptor is opened with the mode already
    set. On Windows this degrades to the directory ACL, which is what
    winservice-kit hardens.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | NOFOLLOW,
                 FILE_MODE)
    with os.fdopen(fd, "w") as fh:
        # O_CREAT only applies the mode to a file it creates, so a file that
        # already existed keeps whatever mode it had. fchmod on the descriptor
        # fixes that before a single byte is written, and cannot be raced by
        # swapping the path underneath us the way a chmod afterwards can.
        try:
            os.fchmod(fh.fileno(), FILE_MODE)
        except (OSError, AttributeError):
            pass                      # not available on Windows
        fh.write(text)


@dataclass(frozen=True)
class Outcome:
    """Result of one attempt. Immutable so it cannot be edited downstream.

    Deliberately does NOT hold the job's full output. A job that prints
    gigabytes would otherwise be buffered entirely in the memory of the process
    whose whole purpose is to stay up and report on it. Only a bounded tail is
    kept; the full streams live in temporary files and are passed through.
    """

    code: int
    empty: bool
    tail: str
    seconds: float


def verdict(out: Outcome, allow_empty: bool) -> str:
    """'ok' | 'fail' | 'empty'. Pure function: easy to test, no side effects."""
    if out.code != 0:
        return "fail"
    if not allow_empty and out.empty:
        return "empty"
    return "ok"


def delays(retries: int, backoff: float) -> list[float]:
    """Waits between attempts, doubling each time."""
    return [backoff * (2**i) for i in range(retries)]


def should_alert(prev_status: str, status: str, streak: int,
                 every: int = REMIND_EVERY) -> bool:
    """Alert on state change, then only every `every` consecutive failures.

    This is the rule that decides whether the alert channel stays useful. A job
    running every 5 minutes with a broken dependency will send 288 messages a
    day if you alert on every failure, and after day one nobody reads the
    channel at all. Alert once when it breaks, once when it recovers, and a
    reminder every `every` failures so a long outage does not fall silent.

    First run is deliberately treated as a change: if the job is already broken
    the moment you install the watchdog, you want to hear about it now. But a
    first run that is healthy stays quiet - no "everything is fine" noise.
    """
    if status == "ok":
        return prev_status not in ("", "ok")
    return streak == 1 or streak % every == 0


def _safe_name(name: str) -> str:
    """Job names become filenames, so they must not be able to escape the dir.

    Without this, a job called "../../.ssh/authorized_keys" writes there.
    Callers are trusted here, but a filename built from an argument is exactly
    the kind of thing that later gets fed from a config file by someone else.
    """
    cleaned = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name)
    cleaned = cleaned.lstrip(".") or "job"
    return cleaned[:64]


def log(name: str, line: str) -> None:
    path = _state_dir() / f"{_safe_name(name)}.log"
    if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
        path.rename(path.with_suffix(".log.1"))
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | NOFOLLOW,
                 FILE_MODE)
    with os.fdopen(fd, "a") as fh:
        fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {line}\n")


def record(name: str, status: str, out: Outcome,
           attempts: int) -> tuple:
    """Persist the outcome. Returns (previous status, consecutive failures)."""
    _state_dir()
    try:
        runs = json.loads(RUNS.read_text()) if RUNS.exists() else {}
    except ValueError:
        runs = {}                 # a truncated state file must not stop the run
    prev = runs.get(name, {})
    prev_status = prev.get("status", "")
    streak = 0 if status == "ok" else int(prev.get("streak", 0)) + 1
    runs[name] = {
        "when": datetime.now().isoformat(timespec="seconds"),
        "status": status,
        "code": out.code,
        "seconds": round(out.seconds, 1),
        "attempts": attempts,
        "streak": streak,
        "tail": out.tail,
    }
    _write_private(RUNS, json.dumps(runs, indent=1))
    return prev_status, streak


def _tail_of(path: Path, limit: int = TAIL_CHARS) -> str:
    """Last `limit` characters of a file, without reading the whole thing."""
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > limit * 4:
                fh.seek(-limit * 4, os.SEEK_END)
            data = fh.read()
    except OSError:
        return ""
    return data.decode("utf-8", "replace")[-limit:].strip()


def _looks_empty(path: Path) -> bool:
    """True if stdout held nothing but whitespace."""
    try:
        if path.stat().st_size == 0:
            return True
        with path.open("rb") as fh:
            head = fh.read(EMPTY_PROBE)
    except OSError:
        return True
    return not head.strip()


def _passthrough(path: Path, stream) -> None:
    """Copy the job's output to ours, in chunks, so memory stays bounded.

    Written as bytes to the underlying buffer rather than decoded text: a
    multi-byte character landing on a chunk boundary would otherwise be split
    and come out as replacement characters. The wrapper must be byte-exact -
    whatever consumed this job's stdout before still gets exactly what it got.
    """
    sink = getattr(stream, "buffer", None)
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(STREAM_CHUNK)
                if not chunk:
                    break
                if sink is not None:
                    sink.write(chunk)
                else:
                    stream.write(chunk.decode("utf-8", "replace"))
        if sink is not None:
            sink.flush()
        stream.flush()
    except (OSError, ValueError):
        pass


def attempt(cmd: list, timeout: float, out_p: Path, err_p: Path) -> Outcome:
    """Run the command once. Every failure mode becomes an Outcome, not a raise.

    Output goes to files rather than pipes: it keeps memory bounded no matter
    how loud the job is, and it removes the pipe-buffer deadlock you get when
    a child fills stderr while you are still reading stdout.

    124 matches the exit code coreutils `timeout` uses, so existing alerting
    that already understands 124 keeps working. 127 is "command not found",
    which is what a bad path in a crontab actually looks like.
    """
    start = time.monotonic()
    try:
        with out_p.open("wb") as o, err_p.open("wb") as e:
            # nosec B603 - running a command is the entire purpose of this
            # tool. The argument list comes from the operator's own crontab,
            # is passed as a list, and never goes through a shell.
            r = subprocess.run(  # noqa: S603  # nosec B603
                cmd, stdout=o, stderr=e, timeout=timeout)
        code = r.returncode
    except subprocess.TimeoutExpired:
        # Append rather than overwrite: whatever the job managed to print
        # before it hung is usually the most useful thing in the alert, and
        # replacing the file would throw it away.
        with err_p.open("ab") as e:
            e.write(f"\n[watchdog] timed out after {timeout}s".encode())
        code = 124
    except Exception as e:        # any failure becomes an Outcome
        with err_p.open("ab") as fh:
            fh.write(f"\n[watchdog] {type(e).__name__}: {e}".encode())
        code = 127
    seconds = time.monotonic() - start
    tail = _tail_of(err_p) or _tail_of(out_p)
    return Outcome(code, _looks_empty(out_p), tail, seconds)


def run(name: str, cmd: list, retries: int, backoff: float,
        timeout: float, allow_empty: bool, quiet: bool) -> int:
    with tempfile.TemporaryDirectory(prefix="job-watchdog-") as tmp:
        out_p, err_p = Path(tmp) / "stdout", Path(tmp) / "stderr"

        out = attempt(cmd, timeout, out_p, err_p)
        status = verdict(out, allow_empty)
        tries = 1
        for wait in delays(retries, backoff):
            if status == "ok":
                break
            log(name, f"attempt {tries} {status} (exit {out.code}), "
                      f"retrying in {wait:.0f}s")
            time.sleep(wait)
            out = attempt(cmd, timeout, out_p, err_p)
            status = verdict(out, allow_empty)
            tries += 1

        log(name, f"{status} in {out.seconds:.1f}s after {tries} attempt(s) "
                  f"(exit {out.code})")
        prev_status, streak = record(name, status, out, tries)

        # The job's own output still goes where it would have gone, streamed
        # rather than buffered. The wrapper stays transparent: whatever
        # consumed this job's stdout keeps working.
        _passthrough(out_p, sys.stdout)
        _passthrough(err_p, sys.stderr)

    if not quiet and should_alert(prev_status, status, streak):
        if status == "ok":
            notify.send(f"OK - {name} is healthy again")
        else:
            # Summary and detail go in as plain text. notify.send() is the only
            # place that knows how each channel wants them encoded, so the
            # job's untrusted output cannot end up escaped for the wrong sink.
            reason = "empty output" if status == "empty" else f"exit {out.code}"
            repeat = f", {streak} in a row" if streak > 1 else ""
            notify.send(
                f"{name} failed: {reason} after {tries} attempt(s){repeat}",
                out.tail or "(no output)",
            )
    return 0 if status == "ok" else 1


def report() -> None:
    print(f"alert channels: {', '.join(notify.configured())}\n")
    if not RUNS.exists():
        print("no runs recorded yet")
        return
    try:
        runs = json.loads(RUNS.read_text())
    except (OSError, ValueError) as exc:
        print(f"state file unreadable ({exc}); it will be rebuilt on the "
              f"next run")
        return
    label = {"ok": "OK", "empty": "EMPTY", "fail": "FAILED"}
    for name, r in sorted(runs.items()):
        streak = f"  ({r['streak']} in a row)" if r.get("streak") else ""
        print(f"{label.get(r['status'], r['status']):<7} {name:<20} {r['when']}  "
              f"{r['seconds']}s  attempts={r['attempts']}{streak}")


def self_test() -> None:
    global STATE_DIR, RUNS          # rebound to a temp dir further down

    ok = Outcome(0, False, "data", 1.0)
    empty = Outcome(0, True, "", 1.0)
    broken = Outcome(1, True, "boom", 1.0)

    assert verdict(ok, False) == "ok"
    assert verdict(empty, False) == "empty"
    assert verdict(empty, True) == "ok"           # --allow-empty
    assert verdict(broken, False) == "fail"
    assert verdict(broken, True) == "fail"        # exit code beats allow_empty

    assert delays(0, 30) == []
    assert delays(3, 30) == [30, 60, 120]

    # alert policy: first failure yes, then silence until the reminder
    assert should_alert("ok", "fail", 1)
    assert not should_alert("fail", "fail", 2)
    assert not should_alert("fail", "fail", 11)
    assert should_alert("fail", "fail", 12)
    assert should_alert("fail", "ok", 0)          # recovery
    assert not should_alert("ok", "ok", 0)        # healthy stays quiet
    assert not should_alert("", "ok", 0)          # healthy first run stays quiet
    assert should_alert("", "empty", 1)           # broken first run speaks up

    # a job name becomes a filename, so it must never escape the state
    # directory - not on POSIX and not on Windows
    for hostile in ("../../.ssh/authorized_keys", "a/b", "..", "...",
                    "..\\..\\windows\\win.ini", "/etc/passwd", ""):
        safe = _safe_name(hostile)
        assert "/" not in safe and "\\" not in safe, safe
        assert not safe.startswith("."), safe
        assert safe, "must never be empty"
        resolved = (STATE_DIR / f"{safe}.log").resolve()
        assert resolved.parent == STATE_DIR.resolve(), resolved
    assert _safe_name("...") == "job"
    assert len(_safe_name("x" * 200)) == 64

    with tempfile.TemporaryDirectory() as tmp:
        out_p, err_p = Path(tmp) / "stdout", Path(tmp) / "stderr"

        # the four real exit paths, executed for real
        def ran(code, timeout=10):
            return attempt([sys.executable, "-c", code], timeout, out_p, err_p)

        assert ran("print('hi')").code == 0
        assert not _looks_empty(out_p)
        assert ran("raise SystemExit(3)").code == 3
        assert _looks_empty(out_p), "stdout must be reset between attempts"
        assert ran("import time;time.sleep(5)", 0.3).code == 124
        assert attempt(["/nonexistent/binary"], 10, out_p, err_p).code == 127

        # whitespace-only output counts as empty
        ran("print('   ')")
        assert _looks_empty(out_p)

        # a loud job must not be buffered into memory, and the tail is bounded
        big = ran("import sys;sys.stderr.write('x'*2_000_000)", 30)
        assert err_p.stat().st_size == 2_000_000
        assert len(big.tail) <= TAIL_CHARS, len(big.tail)

        # a job that hangs must not lose what it printed before hanging: that
        # is usually the only clue about where it got stuck
        hung = ran("import sys,time;sys.stderr.write('reached step 3');"
                   "sys.stderr.flush();time.sleep(5)", 0.5)
        assert hung.code == 124
        assert "reached step 3" in err_p.read_text(), "partial output was destroyed"
        assert "timed out" in hung.tail

        # passthrough must be byte-exact, including a multi-byte character
        # landing on a chunk boundary
        import io
        ran("import sys;sys.stdout.buffer.write("
            "b'a'*65535 + '\u20ac'.encode() + b'b'*10)")
        holder = io.BytesIO()
        shim = type("S", (), {"buffer": holder, "flush": lambda self: None})()
        _passthrough(out_p, shim)
        got = holder.getvalue()
        assert got == out_p.read_bytes(), "passthrough altered the bytes"
        assert "\u20ac" in got.decode("utf-8"), "the euro sign was mangled"

    # a symlink planted where a state file goes must be refused, not followed
    if os.name == "posix":
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim"
            victim.write_text("original")
            bait = Path(tmp) / "bait"
            os.symlink(victim, bait)
            try:
                _write_private(bait, "overwritten")
            except OSError:
                pass                       # ELOOP: exactly what should happen
            assert victim.read_text() == "original", "followed the symlink"

    # State files must not be readable by anyone else. Checked against a
    # throwaway directory: a self-test that writes into the user's real state
    # is a self-test with side effects, and --test must be safe to run anywhere.
    real_dir, real_runs = STATE_DIR, RUNS
    try:
        with tempfile.TemporaryDirectory() as tmp:
            STATE_DIR = Path(tmp) / "state"
            RUNS = STATE_DIR / "runs.json"
            _state_dir()
            probe = STATE_DIR / "permcheck"
            _write_private(probe, "x")
            log("a job/with:slashes", "line")
            record("demo", "fail", broken, 1)
            if os.name == "posix":
                assert probe.stat().st_mode & 0o777 == FILE_MODE
                assert RUNS.stat().st_mode & 0o777 == FILE_MODE
                assert (STATE_DIR / "a_job_with_slashes.log").stat().st_mode \
                    & 0o777 == FILE_MODE
                assert STATE_DIR.stat().st_mode & 0o777 == DIR_MODE

            # an existing world-readable file must be tightened, not trusted
            loose = STATE_DIR / "loose"
            loose.write_text("x")
            os.chmod(loose, 0o644)
            _write_private(loose, "y")
            if os.name == "posix":
                assert loose.stat().st_mode & 0o777 == FILE_MODE, \
                    "an existing file kept its loose mode"
    finally:
        STATE_DIR, RUNS = real_dir, real_runs

    print("OK - job_watchdog.py")


def main() -> int:
    argv = sys.argv[1:]
    if "--test" in argv:
        self_test()
        return 0
    if "--report" in argv:
        report()
        return 0
    if not argv or "--" not in argv or argv[0].startswith("-"):
        print(__doc__)
        return 2

    split = argv.index("--")
    opts, cmd = argv[:split], argv[split + 1:]
    if not cmd:
        print("no command after --", file=sys.stderr)
        return 2

    ap = argparse.ArgumentParser(prog="job_watchdog.py", add_help=False)
    ap.add_argument("name")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--backoff", type=float, default=30)
    ap.add_argument("--timeout", type=float, default=900)
    ap.add_argument("--allow-empty", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(opts)

    return run(args.name, cmd, args.retries, args.backoff, args.timeout,
               args.allow_empty, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
