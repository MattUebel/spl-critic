"""Environment scan: index composition → prompt-guidance suggestions.

Cheap, tsidx-only signals (verified live): 24h event composition per index
via tstats, size/retention via the data/indexes REST collection. The output
is a human-editable guidance draft — the admin applies it, we never write
prompt context silently.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import contextlib
from typing import Any

from spl_critic_app.audit import _oneshot
from spl_critic_app.splunkd_client import SplunkdClient

_COMPOSITION_SPL = "| tstats count where index=* earliest=-24h by index"
_CONCENTRATION_WARN = 0.33  # one index holding a third of events changes risk math

# server-info fields worth keeping on a stored audit run (REST name → ours)
_SERVER_FIELDS = (
    ("serverName", "server_name"),
    ("version", "splunk_version"),
    ("os_name", "os"),
    ("numberOfCores", "cpu_cores"),
    ("physicalMemoryMB", "physical_memory_mb"),
)


def summary(client: SplunkdClient) -> dict[str, Any]:
    """Compact environment fingerprint for stored audit runs.

    Cheap REST reads only (server info + index listing) — no searches. Each
    source is best-effort: a reopened audit shows what it ran against, and a
    failed scan just means an emptier summary, never a slower or failed audit.
    """
    out: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        status, doc = client.get_json("/services/server/info")
        if status == 200:
            content = (doc.get("entry") or [{}])[0].get("content", {}) or {}
            for src, dst in _SERVER_FIELDS:
                value = content.get(src)
                if value not in (None, ""):
                    out[dst] = value
    with contextlib.suppress(Exception):
        status, doc = client.get_json("/services/data/indexes?count=0")
        if status == 200 and doc.get("entry"):
            out["index_count"] = len(doc["entry"])
    return out


def scan(client: SplunkdClient) -> dict[str, Any]:
    counts = {}
    for row in _oneshot(client, _COMPOSITION_SPL):
        name = row.get("index", "")
        if name:
            counts[name] = int(float(row.get("count", 0) or 0))
    total = sum(counts.values())

    meta = {}
    status, doc = client.get_json("/services/data/indexes?count=0")
    if status == 200:
        for entry in doc.get("entry", []):
            content = entry.get("content", {}) or {}
            meta[entry.get("name", "")] = {
                "size_mb": int(float(content.get("currentDBSizeMB", 0) or 0)),
                "retention_days": int(
                    float(content.get("frozenTimePeriodInSecs", 0) or 0) / 86400
                ),
            }

    indexes = [
        {
            "name": name,
            "events_24h": events,
            "pct": round(events / total, 3) if total else 0.0,
            "size_mb": meta.get(name, {}).get("size_mb", 0),
            "retention_days": meta.get(name, {}).get("retention_days", 0),
        }
        for name, events in sorted(counts.items(), key=lambda kv: -kv[1])
    ]
    concentration = indexes[0]["pct"] if indexes else 0.0
    return {
        "indexes": indexes,
        "total_events_24h": total,
        "concentration": concentration,
        "suggested_guidance": suggest_guidance(indexes, total),
    }


def _fmt(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}k"
    return str(n)


def suggest_guidance(indexes: list, total: int) -> str:
    """Deterministic guidance draft from the composition — editable by the admin."""
    if not indexes or total <= 0:
        return ""
    lines = [
        f"Environment profile (auto-scanned): {len(indexes)} active indexes, "
        f"~{_fmt(total)} events/day."
    ]
    top = indexes[0]
    if top["pct"] >= _CONCENTRATION_WARN:
        lines.append(
            f"index={top['name']} dominates with {top['pct']:.0%} of all events "
            f"(~{_fmt(top['events_24h'])}/day) — unscoped, wildcard, or index=* "
            f"searches effectively scan it; treat ill-scoped searches touching it "
            f"as high cost and high risk."
        )
    majors = [i for i in indexes[:5] if i["pct"] >= 0.10 and i is not top]
    if majors:
        lines.append(
            "Other major indexes: "
            + ", ".join(f"index={i['name']} ({i['pct']:.0%})" for i in majors)
            + "."
        )
    quiet = [i["name"] for i in indexes if i["pct"] < 0.01]
    if quiet:
        lines.append(
            "Low-volume indexes (scans there are comparatively cheap): "
            + ", ".join(f"index={n}" for n in quiet[:6])
            + ("…" if len(quiet) > 6 else ".")
        )
    long_ret = [i for i in indexes[:8] if i["retention_days"] >= 365]
    if long_ret:
        lines.append(
            "Long retention (broad time windows are extra expensive): "
            + ", ".join(f"index={i['name']} ({i['retention_days']}d)" for i in long_ret[:4])
            + "."
        )
    return "\n".join(lines)
