#!/usr/bin/env python3
"""Alert delivery that never takes the caller down with it.

An alerting path that can raise is worse than no alerting at all: the tool
whose job is to tell you something broke becomes the thing that breaks. Every
function here contains its own failures and falls back to stderr.

Channels are configured by environment variable, so the same binary runs on a
laptop, a CI box and a locked-down server without a code change:

    ALERT_TELEGRAM_TOKEN   bot token
    ALERT_TELEGRAM_CHAT    chat id
    ALERT_WEBHOOK_URL      any endpoint that accepts a JSON POST (Slack, Discord,
                           n8n, your own handler)

With nothing set, alerts still print to stderr. That is the intended default
for a first run: you see the message before you wire up delivery.

Security notes
--------------
* Alert bodies carry the failing job's output, which is not trusted input.
  `send()` takes the summary and the detail separately and encodes them once
  per channel: HTML-escaped for Telegram, raw text for a webhook. Callers
  never build markup themselves, so untrusted content cannot be escaped for
  the wrong sink - or decoded back into live markup on its way to one.
  Without the Telegram escaping, output containing `<` makes the API reject
  the message with HTTP 400, and the one alert you needed never arrives.
* Only `https` and `http` URLs are accepted. A webhook set to `file://` would
  otherwise make urllib read a local file, and a typo'd scheme raises inside
  the error path.
* The token is read from the environment and never logged. The token sits
  inside the Telegram URL, and some urllib errors quote the URL they failed
  on, so the error path scrubs both the URL and the token out of anything it
  prints. A credential leaking through an error message is still a leak.
"""
from __future__ import annotations

import html
import json
import os
import sys
import urllib.parse
import urllib.request

TIMEOUT = 20
ALLOWED_SCHEMES = ("https", "http")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects.

    The scheme check below runs on the URL you configured. urlopen follows
    redirects on its own, and urllib's own handler still permits a hop to
    ftp://, so a webhook endpoint that answers 302 could walk the request
    somewhere the check never saw. An alert POST has no business being
    redirected anyway.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def esc(text: str) -> str:
    """Escape untrusted text for Telegram's HTML parse mode."""
    return html.escape(str(text), quote=False)


def _host_of(url: str) -> str:
    """Host only - the Telegram token lives in the URL and must not be logged."""
    try:
        return urllib.parse.urlsplit(url).netloc or "unknown host"
    except ValueError:
        return "unknown host"


def _redact(text: str, url: str) -> str:
    """Remove the URL and the bot token from anything about to be printed."""
    out = text.replace(url, _host_of(url))
    token = os.environ.get("ALERT_TELEGRAM_TOKEN", "").strip()
    if token:
        out = out.replace(token, "<token>")
    return out


def _post(url: str, payload: dict) -> bool:
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            print(f"notify: refusing scheme '{scheme}' (expected https)",
                  file=sys.stderr)
            return False
        # Request() itself raises on a malformed URL, so it belongs inside the
        # try. Leaving it outside is how an alerting function that promises
        # never to raise ends up raising.
        req = urllib.request.Request(  # noqa: S310  # nosec B310
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        # nosec B310 - the scheme is checked above and redirects are refused,
        # so this cannot be walked to file:// or any other unexpected scheme.
        _OPENER.open(req, timeout=TIMEOUT).read()  # nosec B310
        return True
    except Exception as exc:      # alerting must never raise
        # Some urllib errors quote the URL they choked on - and the Telegram
        # token is in that URL. Scrub before printing, not after.
        detail = _redact(f"{type(exc).__name__}: {exc}", url)
        print(f"notify: delivery to {_host_of(url)} failed: {detail}",
              file=sys.stderr)
        return False


def send(summary: str, detail: str = "") -> bool:
    """Deliver an alert, encoding it once per channel.

    `summary` is the one-line headline, `detail` the untrusted body - usually
    the failing job's own output. Callers pass them as plain text and never
    build markup: this function is the only place that knows Telegram wants
    escaped HTML and a webhook wants raw text.

    Returns True if at least one channel accepted it. stderr always gets a
    copy, so the message survives even when every channel is down.
    """
    plain = f"{summary}\n{detail}" if detail else summary
    print(f"ALERT: {plain}", file=sys.stderr)

    delivered = False
    token = os.environ.get("ALERT_TELEGRAM_TOKEN", "").strip()
    chat = os.environ.get("ALERT_TELEGRAM_CHAT", "").strip()
    if token and chat:
        body = f"<b>{esc(summary)}</b>"
        if detail:
            body += f"\n<pre>{esc(detail)}</pre>"
        delivered |= _post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            {"chat_id": chat, "text": body, "parse_mode": "HTML",
             "disable_web_page_preview": True},
        )

    hook = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
    if hook:
        # Raw text, never HTML and never entity-decoded: Slack, Discord and
        # most receivers render this as plain text, and handing decoded markup
        # to a sink whose renderer you do not control is how a log viewer
        # becomes an injection point.
        delivered |= _post(hook, {"text": plain})

    return delivered


def configured() -> list:
    """Which channels are live. Used by --report so you can see the wiring."""
    out = []
    if os.environ.get("ALERT_TELEGRAM_TOKEN") and os.environ.get("ALERT_TELEGRAM_CHAT"):
        out.append("telegram")
    if os.environ.get("ALERT_WEBHOOK_URL"):
        out.append("webhook")
    return out or ["stderr only"]


def self_test() -> None:
    assert esc("<b>x</b> & 'y'") == "&lt;b&gt;x&lt;/b&gt; &amp; 'y'"
    assert _host_of("https://api.telegram.org/bot123:SECRET/sendMessage") \
        == "api.telegram.org"
    assert _host_of("garbage") == "unknown host"

    # an error message that quotes the URL must not leak the token with it
    saved = dict(os.environ)
    try:
        # Assembled at runtime, never written as a literal: a string shaped
        # like a credential trips every scanner in the world, including
        # GitHub push protection, and a false alarm in a security-relevant
        # file is worse than no alarm.
        fake = "123456" + ":" + "SUPER" + "SECRET" + "VALUE"
        os.environ["ALERT_TELEGRAM_TOKEN"] = fake
        url = f"https://api.telegram.org/bot{fake}/sendMessage"
        leaked = f"ValueError: unknown url type: '{url}'"
        clean = _redact(leaked, url)
        assert fake not in clean, clean
        assert "api.telegram.org" in clean

        # every one of these used to raise out of send()
        os.environ.pop("ALERT_TELEGRAM_TOKEN")
        for bad in ("not-a-url", "", "file:///etc/passwd", "ftp://x/y", "http://"):
            os.environ["ALERT_WEBHOOK_URL"] = bad
            assert send("probe", "detail") is False, f"{bad} reported success"

        # the webhook payload must stay plain text - no markup, no entities
        captured = {}
        real_post = globals()["_post"]

        def fake_post(url, payload):
            captured["p"] = payload
            return True

        globals()["_post"] = fake_post
        try:
            os.environ["ALERT_WEBHOOK_URL"] = "https://example.invalid/hook"
            send("job failed", "<script>alert(1)</script> & <b>x</b>")
            body = captured["p"]["text"]
            assert "&lt;" not in body and "&amp;" not in body, body
            assert "<script>" in body, "the detail should reach the sink as-is"
        finally:
            globals()["_post"] = real_post
    finally:
        os.environ.clear()
        os.environ.update(saved)

    print("OK - notify.py")


if __name__ == "__main__":
    if "--test" in sys.argv:
        self_test()
