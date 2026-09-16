"""Bulk saved-search audit — the portfolio-level FACT gathering (Act 6).

Enumerates saved searches across ALL apps (predecessor only saw its own app,
capped at 100) and gathers, per search, everything the agent judges with:
the SPL, the schedule and dispatch window, 30 days of scheduler and _audit
telemetry, and config/history flags (disabled-but-scheduled, phantom index,
silent alert, ...). No verdicts are produced here: rows come back PENDING
and the agent's analysis is attached by the audit endpoint (audit_api).
Schedule/telemetry indicator codes are computed on demand as agent inputs.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import contextlib
import json
import re
from typing import Any

from spl_critic_app import (
    datamodels,
    similarity,
    spl_parser,
    vendor_defaults,
)
from spl_critic_app.splunkd_client import SplunkdClient

_SAVED_SEARCHES = "/servicesNS/-/-/saved/searches"
_PAGE_SIZE = 100

# Telemetry hygiene (IS4S/gjanders convention): keep DMA-acceleration searches
# out of the numbers. NB do NOT exclude user=splunk-system-user here — the
# scheduler dispatches saved searches AS that user, so excluding it drops the
# very searches we audit (found live: history went null for every scheduled
# search). The name-joined queries below are self-cleaning anyway (acceleration
# searches never match a real saved-search name); the exclusion matters for the
# BY-reason portfolio aggregates.
_ACCEL_EXCLUDE = 'savedsearch_name!="_ACCELERATE_*"'

# One pass over 30d of scheduler history: skip behavior (two causes — cluster
# concurrency vs self-overlap), what each run produced (result_count), what
# actually fired (alert_actions), and runtime trend (first vs second half).
_SCHEDULER_SPL = (
    f"search index=_internal sourcetype=scheduler earliest=-30d {_ACCEL_EXCLUDE} "
    "| stats count AS runs, "
    'count(eval(status="skipped")) AS skipped, '
    "avg(run_time) AS avg_runtime, "
    'count(eval(status="success" AND result_count=0)) AS zero_runs, '
    'count(eval(status="success")) AS ok_runs, '
    'count(eval(alert_actions!="")) AS actions_fired, '
    'avg(eval(if(_time<relative_time(now(),"-15d@d"),run_time,null()))) AS rt_early, '
    'avg(eval(if(_time>=relative_time(now(),"-15d@d"),run_time,null()))) AS rt_late '
    "BY savedsearch_name"
)

# Historical efficiency for free: _audit records scan/event/result counts for
# every completed run — the deep-analysis evidence at portfolio scale, with
# zero re-execution.
_HISTORY_SPL = (
    "search index=_audit action=search info=completed savedsearch_name=* earliest=-30d "
    f"{_ACCEL_EXCLUDE} "
    "| stats count AS runs, sum(scan_count) AS scanned, sum(event_count) AS kept, "
    "sum(result_count) AS results, avg(result_count) AS avg_results, "
    "max(result_count) AS max_results BY savedsearch_name"
)

# Generating commands that legitimately have no time window — a search that
# starts with one is NOT an all-time offender even with earliest=0 (IS4S
# leading-pipe disambiguation).
_GENERATING_HEADS = {
    "inputlookup", "rest", "mstats", "metadata", "makeresults", "datamodel",
    "tstats", "dbinspect", "inputcsv", "loadjob", "eventcount", "gentimes",
}
_SCAN_HEAVY_PER_RUN_FLOOR = 1000  # avg events scanned/run below this isn't "heavy"

# Config-derived facts (vs the value-screen history tags: silent_alert /
# empty_report / scan_heavy_history / growing / truncated_alert). All of them
# are inputs the agent weighs; the "retire" headline is the agent's call.
CONFIG_FLAGS = {
    "disabled_but_scheduled", "alltime_window", "app_disabled", "phantom_index",
}

# Literal `index=<name>` and `index IN (a, b)` in a retrieval stage. Used to
# catch searches whose every index reads from a name that doesn't exist here.
_INDEX_EQ_RE = re.compile(r"\bindex\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s()|,]+)", re.IGNORECASE)
_INDEX_IN_RE = re.compile(r"\bindex\s+IN\s*\(([^)]*)\)", re.IGNORECASE)

_WINDOW_RE = re.compile(r"-(\d+)([smhdw])")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_WINDOW_INTERVAL_RATIO = 12  # window > 12x interval = re-scanning history every run
# (12x spares common report shapes like a 4h window refreshed every 30m)
_HYPERACTIVE_RUNS_PER_DAY = 720  # <= 2-minute intervals


def window_seconds(earliest: str) -> int | None:
    """Dispatch window size in seconds; None when unknown/unbounded."""
    m = _WINDOW_RE.search(earliest or "")
    if not m:
        return None
    return int(m.group(1)) * _UNITS[m.group(2)]


def schedule_findings(runs_per_day: float, earliest: str) -> list:
    """Schedule-hygiene codes — the checks declared in rules/schedule.yaml."""
    if runs_per_day <= 0:
        return []
    codes = []
    interval_s = 86400 / runs_per_day
    win = window_seconds(earliest)
    if win and win >= 3600 and win > interval_s * _WINDOW_INTERVAL_RATIO:
        codes.append("WINDOW_INTERVAL_MISMATCH")
    if runs_per_day >= _HYPERACTIVE_RUNS_PER_DAY:
        codes.append("HYPERACTIVE_SCHEDULE")
    return codes


_MIN_RUNS_FOR_VALUE = 10  # don't judge a search on a handful of runs
_STARVED_SKIP_RATIO = 0.5  # skipped in the majority of its scheduled cycles
_MIN_RUNS_FOR_HISTORY = 5


def list_saved_searches(client: SplunkdClient) -> list:
    """All saved searches in the environment, paged."""
    entries = []
    offset = 0
    while True:
        status, doc = client.get_json(
            f"{_SAVED_SEARCHES}?count={_PAGE_SIZE}&offset={offset}"
        )
        if status != 200:
            break
        page = doc.get("entry", [])
        entries.extend(page)
        offset += len(page)
        total = (doc.get("paging", {}) or {}).get("total", 0)
        if not page or offset >= total:
            break
    return entries


def cron_runs_per_day(cron: str) -> float:
    """Rough executions/day from a cron schedule — ranking, not scheduling."""
    if not cron or not cron.strip():
        return 0.0
    fields = cron.split()
    if len(fields) != 5:
        return 0.0
    minute, hour = fields[0], fields[1]

    def slots(spec: str, span: int) -> float:
        if spec == "*":
            return span
        m = re.match(r"^\*/(\d+)$", spec)
        if m:
            return max(1.0, span / int(m.group(1)))
        return len(spec.split(","))

    return slots(minute, 60) * slots(hour, 24)


def _oneshot(client: SplunkdClient, spl: str) -> list:
    """Rows from a oneshot search; [] on any failure (enrichment, not blocker)."""
    try:
        status, body = client.post(
            "/services/search/jobs",
            {"search": spl, "exec_mode": "oneshot", "output_mode": "json", "count": "0"},
        )
        if status != 200:
            return []
        return json.loads(body).get("results", [])
    except Exception:
        return []


def _num(row: dict, key: str) -> float:
    try:
        return float(row.get(key) or 0)
    except (TypeError, ValueError):
        return 0.0


def scheduler_stats(client: SplunkdClient) -> dict:
    """Per-saved-search scheduler telemetry (30d): skips, output, firings, trend."""
    stats = {}
    for row in _oneshot(client, _SCHEDULER_SPL):
        name = row.get("savedsearch_name", "")
        runs = _num(row, "runs")
        if not name or runs <= 0:
            continue
        ok_runs = _num(row, "ok_runs")
        stats[name] = {
            "runs_30d": int(runs),
            "skipped_30d": int(_num(row, "skipped")),
            "skip_ratio": round(_num(row, "skipped") / runs, 3),
            "avg_runtime_s": round(_num(row, "avg_runtime"), 1),
            "ok_runs": int(ok_runs),
            "zero_rate": round(_num(row, "zero_runs") / ok_runs, 3) if ok_runs else 0.0,
            "actions_fired_30d": int(_num(row, "actions_fired")),
            "rt_early": _num(row, "rt_early"),
            "rt_late": _num(row, "rt_late"),
        }
    return stats


_EFFICIENCY_BANDS: list = []  # set by set_bands() from the compiled bundle


def set_bands(bundle: dict) -> None:
    """Install the efficiency bands from the knowledge bundle (limits.json)."""
    global _EFFICIENCY_BANDS
    _EFFICIENCY_BANDS = list(
        bundle.get("limits", {}).get("efficiency_bands", {}).get("bands", [])
    )


def history_stats(client: SplunkdClient, bundle_or_bands: Any = None) -> dict:
    """Measured efficiency per saved search from the _audit completion trail."""
    if isinstance(bundle_or_bands, dict):
        bands = bundle_or_bands.get("limits", {}).get("efficiency_bands", {}).get("bands", [])
    else:
        bands = list(bundle_or_bands or _EFFICIENCY_BANDS)
    stats = {}
    for row in _oneshot(client, _HISTORY_SPL):
        name = row.get("savedsearch_name", "")
        scanned = _num(row, "scanned")
        if not name or scanned <= 0:
            continue
        efficiency = (_num(row, "kept") or _num(row, "results")) / scanned
        rating = "unknown"
        for band in bands:
            if efficiency >= band["min"]:
                rating = band["rating"]
                break
        stats[name] = {
            "runs": int(_num(row, "runs")),
            "scanned": int(scanned),
            "results": int(_num(row, "results")),
            "avg_results": round(_num(row, "avg_results"), 1),
            "max_results": int(_num(row, "max_results")),
            "efficiency": round(efficiency, 4),
            "rating": rating,
        }
    return stats


def _is_realtime_dispatch(row: dict) -> bool:
    """True when either dispatch bound uses a real-time (`rt`) time modifier."""
    for bound in (row.get("dispatch_earliest", ""), row.get("dispatch_latest", "")):
        if str(bound).strip().lower().startswith("rt"):
            return True
    return False


def metadata_findings(row: dict, sched: dict | None) -> list:
    """Schedule-health codes needing runtime telemetry + courtesy metadata."""
    if not row["scheduled"] or row["disabled"]:
        return []
    codes = []
    # real-time dispatch (rt- earliest / rt latest) — a continuous search wearing
    # a schedule; config-only, so it fires without any runtime telemetry
    if _is_realtime_dispatch(row):
        codes.append("REALTIME_DISPATCH")
    interval_s = 86400 / row["runs_per_day"] if row["runs_per_day"] else 0
    if sched:
        runtime = sched.get("avg_runtime_s", 0)
        self_overlap = bool(interval_s and runtime > interval_s)
        if self_overlap:
            codes.append("SELF_OVERLAP")
        span = window_seconds(row.get("dispatch_earliest", ""))
        if span and runtime > span:
            codes.append("OVERRUN_RANGE")
        if (
            row.get("actions")
            and row.get("realtime_schedule")
            and sched.get("skipped_30d", 0) > 0
        ):
            codes.append("MISSED_ALERT_WINDOWS")
        # Starvation: skipped in the majority of cycles by contention (not its
        # own runtime) while at default priority — nothing will change, it keeps
        # losing the slot. Distinct from SELF_OVERLAP, whose skips are self-caused.
        if (
            not self_overlap
            and sched.get("runs_30d", 0) >= _MIN_RUNS_FOR_VALUE
            and sched.get("skip_ratio", 0.0) >= _STARVED_SKIP_RATIO
            and row.get("schedule_priority", "default") == "default"
        ):
            codes.append("STARVED_SCHEDULE")
    if (
        row["runs_per_day"] >= 24
        and not row.get("actions")
        and row.get("allow_skew") in ("0", "")
        and row.get("schedule_window") in ("0", "")
    ):
        codes.append("NO_SCHEDULE_COURTESY")
    return codes




def value_flags(row: dict, sched: dict, history: dict | None) -> list:
    """The value screen: does this scheduled search produce anything anyone
    (or anything) consumes? Verified-signal tags only — see docs/ROADMAP.md."""
    flags = []
    if not row["scheduled"] or row["disabled"]:
        return flags
    enough = sched.get("ok_runs", 0) >= _MIN_RUNS_FOR_VALUE
    if enough and row.get("actions") and sched.get("actions_fired_30d", 0) == 0:
        flags.append("silent_alert")
    if (
        enough
        and not row.get("actions")
        and not row.get("summary_index")
        and sched.get("zero_rate", 0.0) >= 0.95
    ):
        flags.append("empty_report")
    if (
        history
        and history["runs"] >= _MIN_RUNS_FOR_HISTORY
        # 0.05, not the 0.10 "poor" band edge: only genuinely wasteful scanners,
        # so a well-scoped search sitting near the band boundary stays clean
        and history["efficiency"] < 0.05
        # gate on real scan volume so a tiny sparse search isn't "heavy"
        and history["scanned"] / max(history["runs"], 1) >= _SCAN_HEAVY_PER_RUN_FLOOR
    ):
        flags.append("scan_heavy_history")
    rt_early, rt_late = sched.get("rt_early", 0.0), sched.get("rt_late", 0.0)
    enough_trend = sched.get("runs_30d", 0) >= 2 * _MIN_RUNS_FOR_VALUE
    if rt_early > 0 and rt_late > rt_early * 1.5 and enough_trend:
        flags.append("growing")
    # payload truncation: an alert action caps results below what the search
    # measurably produces — recipients silently see a fraction of the matches
    cap = row.get("alert_payload_cap")
    if cap and history and history.get("avg_results", 0) > cap:
        flags.append("truncated_alert")
        row["truncation"] = {
            "cap": cap,
            "avg_results": history["avg_results"],
            "max_results": history.get("max_results", 0),
        }
    return flags


def _generating_head(spl: str) -> bool:
    """True when the SPL starts with `| <generating command>` (no time window)."""
    s = (spl or "").lstrip()
    if not s.startswith("|"):
        return False
    m = re.match(r"\|\s*([a-zA-Z_]+)", s)
    return bool(m and m.group(1).lower() in _GENERATING_HEADS)


def config_flags(content: dict) -> list:
    """Config-only facts about a saved search: disabled-but-scheduled and an
    explicit all-time window. Facts, not findings — the agent weighs them."""
    flags = []
    if str(content.get("disabled", "0")) in ("1", "true", "True") and str(
        content.get("is_scheduled", content.get("enableSched", "0"))
    ) in ("1", "true", "True"):
        flags.append("disabled_but_scheduled")
    earliest = str(content.get("dispatch.earliest_time", "") or "")
    # Only explicit all-time counts: an empty dispatch window is common in OOTB
    # searches that bound time inside the SPL — flagging it drowns real zombies
    # (observed: 150/190 flagged on a stock instance before this guard). And a
    # leading generating command (| inputlookup, | rest, | tstats …) is N/A,
    # not all-time, even with earliest=0.
    alltime = earliest == "0" or "alltime" in earliest.lower()
    if alltime and not _generating_head(content.get("search", "")):
        flags.append("alltime_window")
    return flags


def defined_index_names(client: SplunkdClient) -> set:
    """Lowercased names of every index defined on this instance (best-effort).

    Empty set on any failure — callers must treat empty as "unknown" and skip
    phantom-index detection rather than flag everything.
    """
    try:
        status, doc = client.get_json("/services/data/indexes?count=0")
    except Exception:
        return set()
    if status != 200:
        return set()
    names = set()
    for entry in doc.get("entry", []) or []:
        name = (entry.get("name", "") or "").strip().lower()
        if name:
            names.add(name)
    return names


def _retrieval_index_literals(spl: str) -> list | None:
    """Literal index names the retrieval stage reads from.

    Returns None when the answer is unresolvable — a generating search (no index
    read), a macro/token in retrieval, or a wildcard index value — because any of
    those means we cannot conclude the search reads from nowhere.
    """
    retrieval = spl_parser.parse(spl).retrieval
    if retrieval is None:
        return None  # `| tstats ...` etc.
    args = retrieval.args
    if "`" in args or "$" in args:
        return None  # macro expansion / dashboard token — index set unknown
    raw = list(_INDEX_EQ_RE.findall(args))
    for group in _INDEX_IN_RE.findall(args):
        raw.extend(p for p in re.split(r"[,\s]+", group) if p)
    literals = []
    for token in raw:
        name = token.strip().strip("\"'").lower()
        if not name:
            continue
        if "*" in name:
            return None  # a wildcard could still match a real index
        literals.append(name)
    return literals


def phantom_indexes(spl: str, known: set) -> list:
    """Index names the search reads from that don't exist on this instance.

    Non-empty ONLY when EVERY literal index in retrieval is missing — the search
    genuinely reads from nowhere. A partial mismatch (one real index, one typo)
    returns [] so a single good index keeps the search off the zombie list.
    Empty `known` means we can't judge → [].
    """
    if not known:
        return []
    literals = _retrieval_index_literals(spl)
    if not literals:  # None (unresolvable) or [] (no literal index at all)
        return []
    phantom = [n for n in literals if n not in known]
    if len(phantom) == len(literals):
        return sorted(set(phantom))
    return []


def alert_payload_cap(content: dict) -> int | None:
    """Smallest explicit `action.<name>.maxresults` over the enabled actions.

    None when no enabled action sets an explicit cap — the global default
    (email = 10000) is high enough that only an admin-lowered cap truncates, so
    unset = no concern. The most restrictive action caps the delivered payload.
    """
    actions = [a.strip() for a in str(content.get("actions", "") or "").split(",") if a.strip()]
    caps = []
    for action in actions:
        raw = content.get(f"action.{action}.maxresults")
        if raw in (None, ""):
            continue
        with contextlib.suppress(TypeError, ValueError):
            caps.append(int(float(raw)))
    return min(caps) if caps else None


def audit_entry(entry: dict) -> dict[str, Any] | None:
    """Gather one saved-search entry's facts; None when there is nothing to audit.

    No verdict, no scores, no codes: the row is PENDING until the agent has
    judged it (audit_api attaches `analysis`). Everything here is config or
    derived arithmetic the agent will be handed as context.
    """
    content = entry.get("content", {}) or {}
    spl = (content.get("search") or "").strip()
    if not spl:
        return None

    cron = str(content.get("cron_schedule", "") or "")
    runs = cron_runs_per_day(cron)
    earliest = str(content.get("dispatch.earliest_time", "") or "")
    scheduled = str(content.get("is_scheduled", content.get("enableSched", "0"))) in (
        "1", "true", "True",
    )
    acl = entry.get("acl", {}) or {}
    return {
        "name": entry.get("name", ""),
        "app": acl.get("app", ""),
        "owner": acl.get("owner", ""),
        "spl": spl,
        "cron_schedule": cron,
        "runs_per_day": runs,
        "dispatch_earliest": earliest,
        "dispatch_latest": str(content.get("dispatch.latest_time", "") or ""),
        "scheduled": scheduled,
        "disabled": str(content.get("disabled", "0")) in ("1", "true", "True"),
        "actions": str(content.get("actions", "") or ""),
        "alert_payload_cap": alert_payload_cap(content),
        "summary_index": str(content.get("action.summary_index", "0")) in ("1", "true", "True"),
        "realtime_schedule": str(content.get("realtime_schedule", "1")) in ("1", "true", "True"),
        "allow_skew": str(content.get("allow_skew", "0") or "0"),
        "schedule_window": str(content.get("schedule_window", "0") or "0"),
        "schedule_priority": str(content.get("schedule_priority", "default") or "default"),
        "flags": config_flags(content),
        "est_runs_per_month": int(runs * 30),
    }


# Auditor facts (config + measured history) as knowledgebase codes, so the
# agent has words for them. Value-screen facts stay facts in the row's
# `flags`; this is the same information in the vocabulary the agent answers in.
FLAG_CODES = {
    "phantom_index": "PHANTOM_INDEX",
    "disabled_but_scheduled": "DISABLED_BUT_SCHEDULED",
    "app_disabled": "APP_DISABLED",
    "empty_report": "EMPTY_REPORT",
    "silent_alert": "SILENT_ALERT",
    "truncated_alert": "TRUNCATED_ALERT",
    "scan_heavy_history": "SCAN_HEAVY_HISTORY",
    "growing": "GROWING_RUNTIME",
    "near_duplicate": "NEAR_DUPLICATE",
}


def indicator_codes(row: dict) -> list:
    """Schedule + telemetry + fact indicator codes for one row — agent INPUTS.

    Computed on demand at analysis time (never shipped as findings): the
    schedule-shape checks (window vs interval, hyperactive cron), the
    telemetry-backed metadata checks (self-overlap, overrun, starvation,
    real-time dispatch, missed alert windows, no courtesy), and the gathered
    facts (phantom index, silent alert, ...) as their catalog codes.
    """
    codes: list = []
    if row.get("scheduled"):
        codes.extend(
            schedule_findings(row.get("runs_per_day", 0), row.get("dispatch_earliest", ""))
        )
    codes.extend(c for c in metadata_findings(row, row.get("scheduler")) if c not in codes)
    for flag in row.get("flags", []) or []:
        code = FLAG_CODES.get(flag)
        if code and code not in codes:
            codes.append(code)
    return codes


def _cron_minutes(cron: str) -> set:
    """Which minute slots (0-59) a cron occupies."""
    fields = (cron or "").split()
    if len(fields) != 5:
        return set()
    spec = fields[0]
    if spec == "*":
        return set(range(60))
    m = re.match(r"^\*/(\d+)$", spec)
    if m:
        step = max(1, int(m.group(1)))
        return set(range(0, 60, step))
    out = set()
    for part in spec.split(","):
        if part.strip().isdigit():
            out.add(int(part.strip()) % 60)
    return out


def _verdict(row: dict | None) -> str:
    """The agent's verdict for a row, or "" while the row is pending."""
    analysis = (row or {}).get("analysis") or {}
    return str(analysis.get("verdict") or "") if not analysis.get("llm_error") else ""


def portfolio_findings(client: SplunkdClient, rows: list) -> dict[str, Any]:
    """Findings about the schedule as a whole — no single search owns these."""
    scheduled = [r for r in rows if r["scheduled"] and not r["disabled"]]

    histogram = {}
    for row in scheduled:
        for minute in _cron_minutes(row["cron_schedule"]):
            histogram[minute] = histogram.get(minute, 0) + 1
    peak_minute, peak = max(histogram.items(), key=lambda kv: kv[1], default=(0, 0))

    # cron stacking: how concentrated is the schedule on a single cron string?
    cron_counts: dict[str, int] = {}
    for row in scheduled:
        c = (row["cron_schedule"] or "").strip()
        if c:
            cron_counts[c] = cron_counts.get(c, 0) + 1
    top_cron, top_cron_n = max(cron_counts.items(), key=lambda kv: kv[1], default=("", 0))
    n_sched = len(scheduled)
    stacking = {
        "top_cron": top_cron,
        "top_cron_share": round(top_cron_n / n_sched, 3) if n_sched else 0.0,
        "distinct_crons": len(cron_counts),
        "scheduled": n_sched,
    }

    # scan budget: total events the portfolio's scheduled searches read in 30d.
    # Two DISTINCT facts the ROI panel must keep separate (they were conflated):
    #   - concentration: the single biggest CONSUMER — often a well-formed heavy
    #     search (informational; a heavy search is not necessarily a fixable one),
    #     so carry its verdict too.
    #   - recoverable: the scan volume sitting in BLOCKED searches — the waste we
    #     would actually block, the honest "fix this" number.
    scanned_rows = [r for r in scheduled if r.get("history")]
    total_scanned = sum(r["history"]["scanned"] for r in scanned_rows)
    top_row = max(scanned_rows, key=lambda r: r["history"]["scanned"], default=None)
    blocked_scanned = sum(
        r["history"]["scanned"] for r in scanned_rows if _verdict(r) == "blocked"
    )
    scan_budget = {
        "total_scanned_30d": total_scanned,
        "top_contributor": top_row["name"] if top_row else "",
        "top_share": (
            round(top_row["history"]["scanned"] / total_scanned, 3)
            if top_row and total_scanned
            else 0.0
        ),
        "top_verdict": _verdict(top_row) if top_row else "",
        "blocked_scanned_30d": blocked_scanned,
        "blocked_share": (
            round(blocked_scanned / total_scanned, 3) if total_scanned else 0.0
        ),
    }

    capacity = 0
    try:
        status, doc = client.get_json("/services/server/status/limits/search-concurrency")
        if status == 200 and doc.get("entry"):
            capacity = int(
                doc["entry"][0].get("content", {}).get("max_hist_scheduled_searches", 0) or 0
            )
    except Exception:
        pass

    demand_s = sum(
        row["runs_per_day"] * row["scheduler"]["avg_runtime_s"]
        for row in rows
        if row.get("scheduler") and row["scheduled"] and not row["disabled"]
    )
    utilization = round(demand_s / (86400 * capacity), 3) if capacity else None

    skip_reasons = [
        {"reason": r.get("reason", ""), "count": int(_num(r, "count"))}
        for r in _oneshot(
            client,
            "search index=_internal sourcetype=scheduler status=skipped earliest=-7d "
            f"{_ACCEL_EXCLUDE} | stats count by reason | sort -count | head 5",
        )
    ]
    lag_rows = _oneshot(
        client,
        "search index=_internal sourcetype=scheduler status=success earliest=-24h "
        "| eval lag=_time-scheduled_time | stats avg(lag) AS avg_lag max(lag) AS max_lag",
    )
    lag = lag_rows[0] if lag_rows else {}
    return {
        "herd": {
            "peak_minute": int(peak_minute),
            "searches_at_peak": int(peak),
            "capacity": capacity,
            "oversubscription": round(peak / capacity, 1) if capacity else None,
        },
        "utilization": utilization,
        "stacking": stacking,
        "scan_budget": scan_budget,
        "skip_reasons": skip_reasons,
        "lag": {
            "avg_s": round(_num(lag, "avg_lag"), 2),
            "max_s": round(_num(lag, "max_lag"), 2),
        },
    }


def visibility_warning(client: SplunkdClient) -> str | None:
    """Non-admins may not see every app's searches — say so, don't guess."""
    try:
        status, doc = client.get_json("/services/authentication/current-context")
        if status != 200:
            return None
        content = doc.get("entry", [{}])[0].get("content", {})
        caps = content.get("capabilities", []) or []
        if "admin_all_objects" not in caps:
            return (
                "Your role lacks admin_all_objects — searches in apps you cannot "
                "read are missing from this audit."
            )
    except Exception:
        return None
    return None


def disabled_apps(client: SplunkdClient) -> set:
    """App names that are disabled — their scheduled searches never run."""
    apps = set()
    with contextlib.suppress(Exception):
        status, doc = client.get_json("/services/apps/local?search=disabled%3D1&count=0")
        if status == 200:
            for entry in doc.get("entry", []):
                if str(entry.get("content", {}).get("disabled", "0")) in ("1", "true", "True"):
                    apps.add(entry.get("name", ""))
    return apps


def _measured_expense(rows: list) -> None:
    """0-100 measured 30d cost per row, normalized across the portfolio.

    Ranking by cost_score x frequency is an ESTIMATE from the SPL structure;
    this is the MEASURED cost from the audit trail — total events scanned (I/O)
    and total wall-clock (compute), each normalized to the portfolio max and
    averaged. The 'fix this first' number that traces to real history.
    """
    def scanned(r):
        return (r.get("history") or {}).get("scanned", 0)

    def runtime_total(r):
        s = r.get("scheduler") or {}
        return s.get("runs_30d", 0) * s.get("avg_runtime_s", 0)

    max_scan = max((scanned(r) for r in rows), default=0) or 1
    max_rt = max((runtime_total(r) for r in rows), default=0) or 1
    for r in rows:
        r["measured_expense"] = round(
            100 * (0.5 * scanned(r) / max_scan + 0.5 * runtime_total(r) / max_rt), 1
        )


def run_audit(client: SplunkdClient, names: list | None = None) -> dict[str, Any]:
    """Gather every saved search's facts. Rows come back PENDING (no
    analysis); call `finalize()` after attaching the agent's analyses."""
    telemetry = scheduler_stats(client)
    histories = history_stats(client, _EFFICIENCY_BANDS)
    dead_apps = disabled_apps(client)
    known_indexes = defined_index_names(client)  # empty => skip phantom detection
    wanted = set(names) if names else None
    rows = []
    for entry in list_saved_searches(client):
        if wanted is not None and entry.get("name", "") not in wanted:
            continue
        row = audit_entry(entry)
        if row is None:
            continue
        # scheduled search in a disabled app: looks enabled, will never run
        if row["scheduled"] and not row["disabled"] and row["app"] in dead_apps:
            row["flags"].append("app_disabled")
        # reads only from index names that don't exist here (typo / decommissioned)
        phantom = phantom_indexes(row["spl"], known_indexes)
        if phantom:
            row["phantom_indexes"] = phantom
            row["flags"].append("phantom_index")
        stats = telemetry.get(row["name"])
        history = histories.get(row["name"])
        if history:
            row["history"] = history
        if stats:
            row["scheduler"] = stats
            interval_s = 86400 / row["runs_per_day"] if row["runs_per_day"] else 0
            row["self_overlap_risk"] = bool(
                interval_s and stats["avg_runtime_s"] > interval_s
            )
            row["flags"].extend(value_flags(row, stats, history))
        rows.append(row)

    _measured_expense(rows)
    result: dict[str, Any] = {"results": rows, "tier": "agent"}
    with contextlib.suppress(Exception):  # portfolio view is enrichment
        result["portfolio"] = portfolio_findings(client, rows)
    with contextlib.suppress(Exception):  # DMA hygiene — the invisible load
        result["datamodels"] = datamodels.scan(client)
    with contextlib.suppress(Exception):  # near-duplicate saved searches
        result["duplicates"] = similarity.find_clusters(rows)
        # membership is a fact about the row too: the agent should know a
        # search is one of N clones, not judge it in isolation
        cluster_of = {}
        for cluster in result["duplicates"].get("clusters", []):
            for member in cluster.get("members", []):
                cluster_of[(member.get("app", ""), member.get("name", ""))] = cluster["count"]
        for row in rows:
            n = cluster_of.get((row.get("app", ""), row.get("name", "")))
            if n:
                row["duplicate_count"] = n
                if "near_duplicate" not in row["flags"]:
                    row["flags"].append("near_duplicate")
    with contextlib.suppress(Exception):  # vendor-default-enabled schedules
        vd = vendor_defaults.scan(rows)
        if vd.get("count"):
            result["vendor_defaults"] = vd
    warning = visibility_warning(client)
    if warning:
        result["visibility_warning"] = warning
    finalize(result)
    return result


def finalize(result: dict) -> None:
    """Recompute the headline from the agent's analyses: summary counts,
    the ordering (judged rows by agent rank, then pending rows by measured
    cost), and the recoverable share of the scan budget. Idempotent; call
    after every pass that attaches analyses."""
    rows = result.get("results", [])
    summary = {
        "total": len(rows), "analyzed": 0, "pending": 0,
        "blocked": 0, "warn": 0, "approved": 0, "retire": 0,
    }
    for row in rows:
        verdict = _verdict(row)
        if verdict in ("blocked", "warn", "approved"):
            summary["analyzed"] += 1
            summary[verdict] += 1
            if (row.get("analysis") or {}).get("disposition") == "retire":
                summary["retire"] += 1
        else:
            summary["pending"] += 1
    result["summary"] = summary

    def _order(row: dict) -> tuple:
        analysis = row.get("analysis") or {}
        judged = 1 if _verdict(row) else 0
        return (
            -judged,
            -float(analysis.get("rank_score", 0) or 0),
            -float(row.get("measured_expense", 0) or 0),
            -float(row.get("runs_per_day", 0) or 0),
        )

    rows.sort(key=_order)

    budget = (result.get("portfolio") or {}).get("scan_budget")
    if budget is not None:
        scanned_rows = [
            r for r in rows
            if r.get("history") and r.get("scheduled") and not r.get("disabled")
        ]
        total = sum(r["history"]["scanned"] for r in scanned_rows)
        blocked = sum(r["history"]["scanned"] for r in scanned_rows if _verdict(r) == "blocked")
        top = max(scanned_rows, key=lambda r: r["history"]["scanned"], default=None)
        budget["blocked_scanned_30d"] = blocked
        budget["blocked_share"] = round(blocked / total, 3) if total else 0.0
        budget["top_verdict"] = _verdict(top) if top else ""
