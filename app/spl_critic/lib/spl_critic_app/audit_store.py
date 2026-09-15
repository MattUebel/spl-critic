"""Audit-run history in KV Store — trend snapshots plus reopenable full runs.

Two collections share one run_id per user-initiated audit:

  spl_critic_audit_runs    — compact snapshot (verdict counts, retire count, 30d
                             scan budget, herd) per full audit. Feeds "run
                             this monthly, watch blocked fall". Pruned by age.
  spl_critic_audit_results — the COMPLETE result payload (rows with their
                             scheduler/_audit telemetry and agent analyses,
                             portfolio, duplicates, datamodels, health read,
                             environment) so a past run can be reopened in
                             the Auditor. ~0.5MB per run, so pruned by count.

The full payload is stored as one JSON string field (payload_json): KV Store
handles flat records best — deeply nested arrays of objects are subject to
field flattening/type coercion in the collections API, while a single string
field round-trips the payload exactly. The flat fields beside it exist for
queries (sorting, pruning, the runs list).

Upserting by _key=run_id makes recording idempotent per run: the portfolio
AI-enrichment loop re-runs the audit each pass and passes the run_id back, so
one user session yields ONE browsable run whose stored payload is the final
enriched state.

Name-filtered subset audits are NOT recorded — only full runs, so the trend
stays comparable. All writes are best-effort: an audit must succeed even when
KV Store is down. Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import contextlib
import json
import time
import uuid
from typing import Any

from spl_critic_app import kvstore
from spl_critic_app.splunkd_client import SplunkdClient

COLLECTION = "spl_critic_audit_runs"
RESULTS_COLLECTION = "spl_critic_audit_results"
RETENTION_DAYS = 365  # snapshots are tiny — keep a year of trend
MAX_FULL_RUNS = 20  # full payloads are large — keep the newest N


def new_run_id() -> str:
    return uuid.uuid4().hex


def _analyzed(result: dict) -> int:
    return sum(
        1 for r in result.get("results", []) or []
        if (r.get("analysis") or {}).get("verdict")
    )


def snapshot(result: dict, user: str = "") -> dict[str, Any]:
    s = result.get("summary", {})
    portfolio = result.get("portfolio", {})
    return {
        "created_at": int(time.time()),
        "mode": result.get("mode", ""),
        "user": user,
        "total": s.get("total", 0),
        "blocked": s.get("blocked", 0),
        "warn": s.get("warn", 0),
        "approved": s.get("approved", 0),
        "retire": s.get("retire", 0),
        "analyzed": _analyzed(result),
        "total_scanned_30d": (portfolio.get("scan_budget", {}) or {}).get("total_scanned_30d", 0),
        "herd_oversubscription": (portfolio.get("herd", {}) or {}).get("oversubscription"),
        "dm_flagged": (result.get("datamodels", {}) or {}).get("flagged", 0),
    }


def _full_record(run_id: str, result: dict, user: str, created_at: int) -> dict[str, Any]:
    # run_history is a live read (the trend list) — storing it would nest
    # history inside history; everything else is the reopenable run.
    payload = {k: v for k, v in result.items() if k != "run_history"}
    s = result.get("summary", {})
    return {
        "_key": run_id,
        "run_id": run_id,
        "created_at": created_at,
        "user": user,
        "total": s.get("total", 0),
        "blocked": s.get("blocked", 0),
        "retire": s.get("retire", 0),
        "analyzed": _analyzed(result),
        "payload_json": json.dumps(payload),
    }


def _prune_full_runs(client: SplunkdClient, keep: int | None = None) -> None:
    """Keep only the newest N full payloads (count cap, not age)."""
    if keep is None:
        keep = MAX_FULL_RUNS  # read at call time so tests/config can tune it
    # fields= keeps the prune scan tiny — no 0.5MB payloads on the wire
    rows = kvstore.query(
        client, RESULTS_COLLECTION, sort="created_at:-1", fields="_key,created_at"
    )
    stale = [r.get("_key") for r in rows[keep:] if r.get("_key")]
    if stale:
        kvstore.delete_query(client, RESULTS_COLLECTION, {"$or": [{"_key": k} for k in stale]})


def store_run(client: SplunkdClient, result: dict, user: str = "", run_id: str = "") -> str:
    """Persist a full audit run — trend snapshot + complete payload, one run_id.

    Pass the run_id from a previous call to update that run in place (the
    portfolio AI-enrichment loop re-runs the audit each pass; continuity keeps
    it one browsable run with its final enriched state). Returns the run_id
    used — even when KV Store is down, so a client can keep passing it and the
    record appears once the store recovers.
    """
    rid = run_id or new_run_id()
    created = 0
    if run_id:  # continuation: keep the original run timestamp
        prev = kvstore.get_one(client, COLLECTION, rid)
        if prev:
            with contextlib.suppress(TypeError, ValueError):
                created = int(prev.get("created_at") or 0)
    if not created:
        created = int(time.time())

    snap = snapshot(result, user)
    snap["_key"] = rid
    snap["run_id"] = rid
    snap["created_at"] = created
    if kvstore.upsert(client, COLLECTION, [snap]):
        # audits are infrequent — pruning on write is cheap here
        cutoff = int(time.time()) - RETENTION_DAYS * 86400
        kvstore.delete_query(client, COLLECTION, {"created_at": {"$lt": cutoff}})

    if kvstore.upsert(client, RESULTS_COLLECTION, [_full_record(rid, result, user, created)]):
        _prune_full_runs(client)
    return rid


def get_run(client: SplunkdClient, run_id: str) -> dict | None:
    """The complete stored payload for one run — None when missing/unreadable."""
    rec = kvstore.get_one(client, RESULTS_COLLECTION, run_id)
    if not rec:
        return None
    try:
        payload = json.loads(rec.get("payload_json") or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    payload["run_id"] = rec.get("run_id") or run_id
    payload["created_at"] = rec.get("created_at", 0)
    payload.setdefault("user", rec.get("user", ""))
    return payload


def recent_runs(client: SplunkdClient, limit: int = 12) -> list:
    return kvstore.query(client, COLLECTION, sort="created_at:-1", limit=limit)
