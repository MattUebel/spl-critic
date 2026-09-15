"""Vendor-default scheduled searches — "you never turned these on."

Apps ship saved searches enabled in their `default/savedsearches.conf`. If the
admin never overrode that in `local/`, the search runs on a schedule that nobody
here chose — invisible load inherited from every app you installed.

Attribution needs the conf *layer*, which the merged saved/searches REST view
hides. The app's Python runs as the splunk user with $SPLUNK_HOME set, so we read
each app's `local/savedsearches.conf` directly and ask: is this search's
enablement set locally? If not, its schedule came from the vendor default.

Single-instance only (reads local conf off this box's disk). Best-effort: any
failure (no $SPLUNK_HOME, unreadable file) yields no annotations, never an error.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Keys an admin sets in local/ when they deliberately enable a search. Presence
# of any of these in the local stanza means "the admin chose this" — not vendor.
_LOCAL_ENABLE = ("enableSched", "is_scheduled")


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "t", "yes")


def parse_conf_stanzas(text: str) -> dict[str, dict[str, str]]:
    """Lenient Splunk .conf reader: {stanza: {key: value}}.

    Only single-line `key = value` pairs are captured (enough for the enablement
    keys); line-continued values like multi-line `search = …\\` contribute
    harmless stray keys we never read. Comments and blanks are skipped.
    """
    stanzas: dict[str, dict[str, str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            stanzas.setdefault(current, {})
        elif current is not None and "=" in line:
            key, _, value = line.partition("=")
            stanzas[current][key.strip()] = value.strip()
    return stanzas


def local_enabled_stanzas(local_conf: Path) -> set:
    """Stanza names whose enablement is set in this local/savedsearches.conf."""
    try:
        text = local_conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    enabled = set()
    for name, opts in parse_conf_stanzas(text).items():
        # admin turned scheduling on, or explicitly un-disabled the search
        locally_scheduled = any(_truthy(opts.get(k)) for k in _LOCAL_ENABLE)
        locally_undisabled = "disabled" in opts and not _truthy(opts.get("disabled"))
        if locally_scheduled or locally_undisabled:
            enabled.add(name)
    return enabled


def annotate(rows: list, apps_root: Path) -> dict[str, Any]:
    """Flag rows whose schedule is vendor-default-enabled; return a rollup.

    A row qualifies when it is scheduled, enabled, owned by `nobody` (app-level,
    not a user's private search under etc/users/), and its stanza is NOT locally
    enabled in its app. Adds a soft `vendor_default` flag (not a hard zombie —
    it's awareness, not proven waste) and records `vendor_default: True`.
    """
    local_cache: dict[str, set] = {}
    by_app: dict[str, int] = {}
    flagged = 0
    for row in rows:
        if not (row.get("scheduled") and not row.get("disabled")):
            continue
        if row.get("owner") != "nobody":
            continue  # user-owned searches live under etc/users, not app local/
        app = row.get("app", "")
        if not app:
            continue
        if app not in local_cache:
            local_cache[app] = local_enabled_stanzas(
                apps_root / app / "local" / "savedsearches.conf"
            )
        if row.get("name", "") in local_cache[app]:
            continue  # admin enabled it locally — not a vendor default
        row.setdefault("flags", []).append("vendor_default")
        row["vendor_default"] = True
        flagged += 1
        by_app[app] = by_app.get(app, 0) + 1
    return {
        "count": flagged,
        "by_app": [
            {"app": a, "count": c}
            for a, c in sorted(by_app.items(), key=lambda kv: -kv[1])
        ],
    }


def scan(rows: list) -> dict[str, Any]:
    """Resolve $SPLUNK_HOME and annotate; {} when unavailable (best-effort)."""
    home = os.environ.get("SPLUNK_HOME")
    if not home:
        return {}
    apps_root = Path(home) / "etc" / "apps"
    if not apps_root.is_dir():
        return {}
    return annotate(rows, apps_root)
