"""Redaction preflight — strip secrets from SPL before it reaches the LLM.

The deterministic tier parses the real SPL (it needs to); only the LLM path
is redacted, because that is the only place SPL text leaves the instance. Two
classes of secret:
  - Splunk encrypted-value prefixes ($1$, $6$, $7$, $8$) — the on-disk form of
    stored credentials that can surface in `| rest` output or pasted config.
  - key=value pairs whose key is on a denylist (password, token, api_key, …).

Idea adopted from Admin's Little Helper's redaction pattern; reimplemented.
Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import re

# Splunk stored-secret prefixes: $<scheme>$<salt-or-payload>. Match the prefix
# plus the following non-space run.
_ENCRYPTED_RE = re.compile(r"\$[1678]\$[^\s\"'|\]]+")

DEFAULT_DENY_KEYS = (
    "password", "passwd", "pass", "token", "api_key", "apikey", "api_token",
    "secret", "secret_key", "client_secret", "access_key", "private_key",
    "auth", "authorization", "credential", "credentials", "bearer", "session_key",
)

_PLACEHOLDER = "REDACTED"


def _deny_pattern(deny_keys) -> re.Pattern:
    keys = "|".join(re.escape(k) for k in deny_keys)
    # key = "quoted value"  OR  key = TERM(...)  OR  key = bare_token
    return re.compile(
        rf'(?i)\b({keys})\s*=\s*("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^\s"\'|\]]+)'
    )


def redact_spl(text: str, deny_keys=DEFAULT_DENY_KEYS) -> tuple[str, int]:
    """Return (redacted text, number of values redacted)."""
    if not text:
        return text, 0
    count = 0

    # Denylist first: a `token=$7$…` value is caught here as one redaction, so
    # the encrypted pass below doesn't double-count it.
    def _kv(m):
        nonlocal count
        count += 1
        return f"{m.group(1)}={_PLACEHOLDER}"

    out = _deny_pattern(deny_keys).sub(_kv, text)

    def _enc(_m):
        nonlocal count
        count += 1
        return f"${_PLACEHOLDER}$"

    out = _ENCRYPTED_RE.sub(_enc, out)
    return out, count
