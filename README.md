# job-watchdog

**Know when a scheduled job stops working — including when it keeps succeeding.**

Python 3.9+, standard library only, no dependencies, no agent, no server.

---

## The problem

A job that crashes is the easy case. It has an exit code, and cron, launchd or
the Task Scheduler will show it.

The expensive case is the job that exits `0` and produces nothing. An upstream
retired a feed, or started answering `403`, and the parser dutifully returned an
empty list. Every dashboard stays green. Nobody finds out until somebody asks
why a report has been blank since March.

I lost two production pipelines exactly this way. Both "succeeded" every single
run, for weeks.

`job-watchdog` treats three things as failure:

| Condition | Why it counts |
|---|---|
| exit code `!= 0` | the obvious one |
| timeout | a job that hangs forever is not a job that is running |
| empty stdout | success with no output, unless you pass `--allow-empty` |

## Try it in 30 seconds

```bash
git clone https://github.com/LUCA-MAURI/job-watchdog && cd job-watchdog

# a job that "succeeds" and produces nothing - the silent failure.
# --retries 0 keeps the demo instant; the real default is 2 retries, 30s apart.
python3 job_watchdog.py demo-import --retries 0 -- /bin/sh -c "exit 0"
# ALERT: demo-import failed: empty output after 1 attempt(s)

# a job that fails, retried once a second later
python3 job_watchdog.py demo-sync --retries 1 --backoff 1 -- /bin/sh -c "echo 'connection refused' >&2; exit 2"
# ALERT: demo-sync failed: exit 2 after 2 attempt(s)
#        connection refused

# Run either of those a second time and it stays silent. That is deliberate -
# see "Alert fatigue" below. --report always shows the current state.

# what every supervised job did last
python3 job_watchdog.py --report

python3 job_watchdog.py --test        # self-test, no network, no side effects
```

State lives in `~/.local/state/job-watchdog/`. Delete that directory to reset
the demo.

Nothing changes inside the job. You put the wrapper in front of the command:

```cron
*/15 * * * *  /usr/local/bin/job_watchdog.py sync -- /opt/app/sync.sh
```

stdout and stderr still go where they went before, so whatever consumed the
job's output keeps working.

## Alert fatigue is a design problem, not a config problem

A job running every 5 minutes with a broken dependency sends **288 messages a
day** if you alert on every failure. After day one nobody reads the channel, and
you have spent your alerting budget on noise.

The rule in `should_alert()`:

- alert once when it breaks;
- stay silent while it stays broken;
- remind every 12th consecutive failure, so a long outage never falls silent;
- alert once when it recovers;
- a **first run that is broken** speaks up immediately — if it was already dead
  when you installed the watchdog, you want to know now;
- a first run that is healthy stays quiet. No "everything is fine" noise.

That rule is pure and tested. It is the part most worth stealing even if you
never use the rest.

## Processes that never exit

`job_watchdog.py` supervises jobs that start, work and finish. A long-running
service fails differently: the process is alive, the supervisor shows green, and
it has done nothing useful since Tuesday. A revoked token, a socket that will
never time out, a dependency now returning empty pages — none of these kill the
process.

`deadman.py` covers that. The service proves it is *working*, not merely
*running*:

```python
import deadman

while True:
    result = do_work()
    deadman.beat("heartbeat/importer.txt")   # after the work, never before
```

```json
{"watch": [
   {"name": "importer", "file": "heartbeat/importer.txt", "max_age_min": 15}
]}
```

```bash
python3 deadman.py            # check and alert
python3 deadman.py --report   # status only, sends nothing
```

Placement matters more than the code. A heartbeat written at the *top* of the
loop only proves the loop is spinning, which is the thing you already knew.

`missing` and `illegible` are kept distinct from `stale` on purpose: they mean
different things at 3am. Stale is a service that stopped working. Missing is
usually a wrong path in a config — not an outage.

## Alert routing

Environment variables, so the same binary runs on a laptop, in CI and on a
locked-down server with no code change:

```bash
ALERT_TELEGRAM_TOKEN=...   ALERT_TELEGRAM_CHAT=...
ALERT_WEBHOOK_URL=...      # Slack, Discord, n8n, your own endpoint
```

With nothing set, alerts print to stderr — the intended default for a first run.

Delivery never raises. An alerting path that can throw is worse than no
alerting: the tool whose job is to tell you something broke becomes the thing
that breaks.

## Security

The tool sits between a job and your alert channel, so it handles two things
that are not trustworthy: the job's output, and whatever an upstream put in it.

- **State files are owner-only.** `~/.local/state/job-watchdog/` is `0700` and
  the files inside are `0600`. The mode is applied to the file descriptor
  before a byte is written, not chmod-ed afterwards, so there is no window and
  no path to race. They hold the tail of a failing job's output, which is
  exactly where a token in a stack trace ends up.
- **Symlinks are refused, not followed.** Every state and log file is opened
  `O_NOFOLLOW`. Otherwise anyone able to write into the state directory - which
  includes a machine where an older version left it `0755` - could point
  `runs.json` at a file of their choosing and have this process truncate it.
  The same applies to `deadman.beat()`, which often runs as root or SYSTEM.
- **Alert bodies are HTML-escaped.** Telegram's HTML parse mode rejects a
  message containing a stray `<` with HTTP 400 - so without escaping, a job
  that prints `<` produces no alert at all. The one you needed is the one that
  never arrives.
- **Output is streamed, never buffered.** A job printing 200 MB moves the
  watchdog's peak memory by about 5 MB. Output goes to temporary files rather
  than pipes, which also removes the classic deadlock where a child fills
  stderr while the parent is still reading stdout.
- **Job names are sanitised before becoming filenames.** A job called
  `../../.ssh/authorized_keys` writes inside the state directory, nowhere else.
- **Each channel gets content encoded for it.** `notify.send()` takes the
  summary and the untrusted detail separately: HTML-escaped for Telegram, raw
  plain text for a webhook. Callers never build markup, so nothing gets escaped
  for the wrong sink or decoded back into live markup on the way to one.
- **Alert delivery never raises**, refuses non-HTTP schemes, and scrubs both
  the URL and the token out of anything it prints. Some urllib errors quote
  the URL they failed on, and the Telegram token lives inside that URL - a
  credential leaking through an error message is still a leak.

It does **not** sandbox the command it runs: a supervised job executes with
your privileges. Supervise commands you trust. See [SECURITY.md](SECURITY.md).

## Verify it yourself

Do not take the section above on trust - it is the kind of claim that is easy
to make and cheap to get wrong. Everything is checked by standard tools, in one
command:

```bash
./check.sh
```

| Tool | What it covers |
|---|---|
| self-tests | the behaviour each module claims, run for real |
| ruff | lint, latent bugs, and the `S` security ruleset |
| bandit | Python security scanner (OWASP-oriented) |
| mypy | static types |
| semgrep | dataflow analysis, `p/python` + `p/security-audit` |
| gitleaks | credentials, in the tree and in the history |
| shellcheck | the shell scripts |
| PSScriptAnalyzer | the PowerShell, using Microsoft's own linter |

Current status: **ALL CLEAR** on every one of them.

A tool that is not installed is skipped rather than failing, so the script is
usable before you have all of them - but a skipped tool is never counted as a
pass. The final line only says `ALL CLEAR` when every tool actually ran;
otherwise it tells you how many did not.

Where a finding is suppressed, the suppression sits next to the code with the
reason written out - `# noqa`, `# nosec`, `# nosemgrep`, or an entry in
`pyproject.toml`. There are four kinds, and no others: asserts inside
self-tests, the `subprocess` call that is the entire point of the tool, a
`urlopen` whose scheme is validated and whose redirects are refused, and a
`chmod` to `0o700` that semgrep flags because it cannot resolve the constant
and suggests the looser `0o644` instead.

## What it deliberately does not do

- **No distributed state.** One machine, one JSON file under
  `~/.local/state/job-watchdog/`. If you need fleet-wide visibility you want
  Prometheus, not this.
- **No daemon.** It runs when your scheduler runs it, and exits. Nothing to
  keep alive, nothing to monitor the monitor.
- **No metrics or history.** Last outcome per job, and that is all. It answers
  "is it broken", not "how has latency trended".
- **Not a scheduler.** cron, launchd and the Task Scheduler are fine. This wraps
  them.

## Related

- [resilient-poller](https://github.com/LUCA-MAURI/resilient-poller) — circuit
  breaker and structured logging for services that poll flaky third parties.
- [winservice-kit](https://github.com/LUCA-MAURI/winservice-kit) — ship a Python
  service to a Windows box as a double-clickable installer.

MIT licensed. Built out of running a dozen unattended services across macOS and
Windows and getting tired of finding out late.
