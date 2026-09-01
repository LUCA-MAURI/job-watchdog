# Security

## Reporting

Open a GitHub issue. Do not include a real credential in it - describe the
shape of the problem instead. If a finding is sensitive, say so in the issue
without the details and I will follow up privately.

## Threat model

These tools run **on a machine you control**, supervising **jobs you wrote**.
They are not multi-tenant, they accept no network input, and they expose no
listening port. The realistic risks are therefore:

1. **Credential leakage through observability.** A failing job prints a token
   in a stack trace; the tool records it in state, writes it to a log, and
   sends it to a chat. Handled by: owner-only file modes (0600 files, 0700
   directories on POSIX; a restrictive ACL on Windows) applied at creation
   time and preserved across log rotation, bounded tails, and scrubbing the
   alert token out of error messages - urllib quotes the URL it failed on, and
   the token is in that URL.
2. **Untrusted content reaching a terminal or an API.** Job output and log
   values come from upstreams you do not control. They are HTML-escaped before
   being sent to a chat API, and control characters are neutralised before
   being printed to a terminal.
3. **Local privilege escalation on Windows.** A service running as SYSTEM out
   of a directory an ordinary user can write to is an escalation path. See
   winservice-kit.
4. **Resource exhaustion.** A supervised job that prints without bound must
   not exhaust the memory of the process supervising it.

5. **Symlink substitution.** Every file these tools create is opened
   `O_NOFOLLOW`. Without it, anyone able to write into a state or heartbeat
   directory could point a file at a target of their choosing and have the
   process - which may be running as root or SYSTEM - truncate it.

## What is explicitly out of scope

- Defending against a **malicious job**. If you supervise a command, it runs
  with your privileges; nothing here sandboxes it. Supervise commands you
  trust.
- Defending against an attacker who is **already root or Administrator**.
- Encryption at rest. File modes and ACLs, not encryption. Full-disk
  encryption is the right layer for that.
- Multi-tenant isolation. One machine, one owner.

## Please do not

Do not put credentials in a config file, a job name, or a service definition.
Use environment variables or a secret manager. Every tool here reads its own
secrets from the environment for that reason.
