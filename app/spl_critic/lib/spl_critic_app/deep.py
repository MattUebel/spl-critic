"""Deep analysis: guarded execution + Job Inspector evidence.

Turns "this might be expensive" into "this IS expensive": run the search
under guards (side-effect blocklist, | head cap, bounded window, hard
timeout), read scanCount/eventCount/resultCount off the job, and grade
filtering efficiency against the bands shipped in the knowledge bundle.
Also parser-validates suggested rewrites so nothing unparseable is ever
shown on stage.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
import time
from typing import Any

from spl_critic_app import spl_parser
from spl_critic_app.splunkd_client import SplunkdClient

GUARD_HEAD = 1000
GUARD_EARLIEST = "-60m@m"
GUARD_TIMEOUT_S = 30
_JOBS = "/servicesNS/nobody/spl_critic/search/jobs"


def side_effect_commands(bundle: dict) -> set:
    commands = bundle.get("command_types", {}).get("commands", {})
    return {name for name, spec in commands.items() if spec.get("side_effects")}


def guard(spl: str, bundle: dict) -> tuple[str | None, str]:
    """(guarded SPL, refusal reason). Refuses side-effecting pipelines."""
    pipeline = spl_parser.parse(spl)
    blocked = side_effect_commands(bundle)
    offenders = sorted({c for c in pipeline.commands() if c in blocked})
    if offenders:
        return None, f"refusing guarded execution: side-effect commands {offenders}"
    return f"{spl.strip()} | head {GUARD_HEAD}", ""


def _job_field(content: dict, key: str) -> float:
    try:
        return float(content.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _grade(efficiency: float, bundle: dict) -> tuple[str, str]:
    bands = bundle.get("limits", {}).get("efficiency_bands", {}).get("bands", [])
    for band in bands:  # bands ship sorted by min descending
        if efficiency >= band["min"]:
            return band["rating"], band["action"]
    return "unknown", ""


_UNBOUNDED = ("", "0", "@0", "0.000", "alltime", "all-time")


def guard_window(context: dict | None) -> tuple[str, str]:
    """The execution window: the search's real dispatch window when it is
    bounded, else the default guard window. An unbounded window is never
    executed — evidence sampling stays cheap by construction."""
    if not context:
        return GUARD_EARLIEST, "now"
    earliest = str(context.get("earliest", "") or "").strip()
    latest = str(context.get("latest", "") or "").strip() or "now"
    if earliest.lower() in _UNBOUNDED:
        return GUARD_EARLIEST, "now"
    return earliest, latest


def run_guarded(
    client: SplunkdClient, spl: str, bundle: dict, context: dict | None = None
) -> dict[str, Any]:
    """Execute under guards and return measured evidence (or {'error': ...})."""
    guarded, refusal = guard(spl, bundle)
    if guarded is None:
        return {"error": refusal}

    earliest, latest = guard_window(context)
    search = guarded if guarded.lstrip().startswith("|") else f"search {guarded}"
    status, body = client.post(
        _JOBS,
        {
            "search": search,
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
            "timeout": str(GUARD_TIMEOUT_S * 2),  # server-side job TTL
        },
    )
    if status not in (200, 201):
        return {"error": f"dispatch failed ({status}): {body[:200]!r}"}
    try:
        sid = json.loads(body)["sid"]
    except (ValueError, KeyError):
        return {"error": f"no sid in dispatch response: {body[:200]!r}"}

    deadline = time.time() + GUARD_TIMEOUT_S
    content: dict = {}
    while time.time() < deadline:
        status, doc = client.get_json(f"{_JOBS}/{sid}")
        if status != 200:
            return {"error": f"job poll failed ({status})"}
        entries = doc.get("entry", [])
        content = entries[0].get("content", {}) if entries else {}
        if str(content.get("isDone")) in ("1", "true", "True"):
            break
        time.sleep(1)
    else:
        client.post(f"{_JOBS}/{sid}/control", {"action": "cancel"})
        return {"error": f"guarded run exceeded {GUARD_TIMEOUT_S}s and was cancelled"}

    scan = _job_field(content, "scanCount")
    events = _job_field(content, "eventCount")
    results = _job_field(content, "resultCount")
    numerator = events or results
    efficiency = (numerator / scan) if scan > 0 else 1.0
    rating, action = _grade(efficiency, bundle)

    client.delete(f"{_JOBS}/{sid}")  # tidy: no orphaned demo jobs
    return {
        "sid": sid,
        "guarded_spl": guarded,
        "guard_window": earliest,
        "scan_count": int(scan),
        "event_count": int(events),
        "result_count": int(results),
        "run_duration_s": round(_job_field(content, "runDuration"), 2),
        "efficiency": round(efficiency, 4),
        "rating": rating,
        "action": action,
    }


def validate_rewrite(client: SplunkdClient, spl: str) -> bool:
    """True when the suggested SPL parses (services/search/parser)."""
    q = spl if spl.lstrip().startswith("|") else f"search {spl}"
    status, _body = client.post("/services/search/parser", {"q": q, "output_mode": "json"})
    return status == 200
