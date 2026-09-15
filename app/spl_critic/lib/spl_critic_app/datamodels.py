"""Data-model acceleration hygiene — the invisible scheduled load.

Every accelerated data model runs a summarization search on a cron (default
every 5 minutes) forever. Nobody sees these in the saved-search list, yet a DM
accelerated over all-time, or whose constraints lack an index scope, is a
standing tax on the whole cluster. This reads acceleration CONFIG (not summary
state), so a misconfigured DM flags immediately — no waiting for summaries.

Signals (config-readable via /datamodel/model):
  accel_broad_range  — accelerated with an all-time or >90d earliest window
  accel_unscoped     — accelerated DM whose constraints name no index

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
import re
from typing import Any

from spl_critic_app.splunkd_client import SplunkdClient

# NB no output_mode here — the splunkd client appends it; a duplicate is a 400.
_MODELS = "/servicesNS/-/-/datamodel/model?count=0"
_BROAD_RANGE_S = 90 * 86400  # acceleration window beyond ~90d is a standing scan

# relative-time spans in acceleration earliest_time ("-1y", "-3mon", "-30d", …)
_SPAN_RE = re.compile(r"-(\d+)\s*(mon|y|w|d|h|m|s)", re.IGNORECASE)
_SPAN_UNITS = {
    "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800,
    "mon": 2592000, "y": 31536000,
}


def _earliest_span_seconds(earliest: str) -> int | None:
    """Seconds covered by an acceleration earliest_time; None if all-time."""
    e = (earliest or "").strip().lower()
    if e in ("", "0", "@d", "@h"):
        return None  # empty/anchored-only = effectively all-time
    m = _SPAN_RE.search(e)
    return int(m.group(1)) * _SPAN_UNITS[m.group(2)] if m else None


def _constraints_have_index(model_json: str) -> bool:
    """True when any root constraint/base search names an index."""
    try:
        model = json.loads(model_json or "{}")
    except (ValueError, TypeError):
        return True  # can't tell → don't false-flag
    blob_parts = []
    for obj in model.get("objects", []):
        for c in obj.get("constraints", []) or []:
            blob_parts.append(str(c.get("search", "")))
        if obj.get("baseSearch"):
            blob_parts.append(str(obj["baseSearch"]))
    blob = " ".join(blob_parts)
    if not blob.strip():
        return True  # search-based / no parseable constraints → don't flag
    return bool(re.search(r"(?i)\bindex\s*(=|\bIN\b)", blob))


def scan(client: SplunkdClient) -> dict[str, Any]:
    """Enumerate data models; return accelerated ones with hygiene flags."""
    status, doc = client.get_json(_MODELS)
    if status != 200:
        return {"models": [], "accelerated": 0, "flagged": 0}

    models = []
    for entry in doc.get("entry", []):
        content = entry.get("content", {}) or {}
        try:
            accel = json.loads(content.get("acceleration", "{}") or "{}")
        except (ValueError, TypeError):
            accel = {}
        enabled = str(accel.get("enabled", False)).lower() in ("1", "true", "yes")
        if not enabled:
            continue
        earliest = str(accel.get("earliest_time", ""))
        span = _earliest_span_seconds(earliest)
        flags = []
        if span is None or span > _BROAD_RANGE_S:
            flags.append("accel_broad_range")
        if not _constraints_have_index(content.get("description", "")):
            flags.append("accel_unscoped")
        acl = entry.get("acl", {}) or {}
        models.append({
            "name": entry.get("name", ""),
            "app": acl.get("app", ""),
            "earliest": earliest or "all-time",
            "cron": str(accel.get("cron_schedule", "")),
            "flags": flags,
        })

    return {
        "models": sorted(models, key=lambda m: -len(m["flags"])),
        "accelerated": len(models),
        "flagged": sum(1 for m in models if m["flags"]),
    }
