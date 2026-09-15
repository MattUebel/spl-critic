"""Persistent inference cache + history in KV Store.

Every LLM critique is stored keyed on hash(spl + mode + ruleset_version +
models) — the same key the in-process LRU uses. The collection doubles as the
history: a get-by-key is the cache; a sorted scan is the audit trail. This
survives restarts and lets a re-audit of the same scheduled searches reuse the
inference instead of re-paying for it.

The record carries what the inference cost and produced (model, verdict,
disposition, rewrite, $ cost) so history/stats views can answer "what have we
spent, on what, with which model". Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
import time
from typing import Any

from spl_critic_app import kvstore
from spl_critic_app.splunkd_client import SplunkdClient

COLLECTION = "spl_critic_inference"
_SPL_CAP = 1200  # keep records small
RETENTION_DAYS = 90  # prune inference records older than this (bounded collection)


def build_record(
    key: str,
    spl: str,
    result: dict,
    user: str = "",
    source: str = "critique",
    search_name: str = "",
    app: str = "",
) -> dict[str, Any]:
    return {
        "_key": key,
        "spl": spl[:_SPL_CAP],
        "source": source,
        "search_name": search_name,
        "app": app,
        "user": user,
        "model": result.get("model", ""),
        "verdict": result.get("verdict", ""),
        "risk_score": result.get("risk_score", 0),
        "cost_score": result.get("cost_score", 0),
        "disposition": result.get("disposition", ""),
        "added_codes": (result.get("inputs") or {}).get("added", []),
        "suggested_spl": result.get("suggested_spl") or "",
        "summary": result.get("summary", ""),
        "cost_usd": float((result.get("usage") or {}).get("cost", 0) or 0),
        "latency_ms": result.get("latency_ms", 0),
        "redactions": result.get("redactions", 0),
        "ruleset_version": result.get("ruleset_version", ""),
        "created_at": int(time.time()),
        # full result for cache reconstruction (flat fields above are for
        # queryable history/stats)
        "result_json": json.dumps(result),
    }


def result_from_record(record: dict) -> dict | None:
    """Rebuild the full critique result stored in a cache record."""
    try:
        return json.loads(record["result_json"])
    except (KeyError, ValueError, TypeError):
        return None


def get_cached(client: SplunkdClient, key: str) -> dict | None:
    return kvstore.get_one(client, COLLECTION, key)


def store(client: SplunkdClient, record: dict) -> bool:
    return kvstore.upsert(client, COLLECTION, [record])


def history(client: SplunkdClient, limit: int = 50) -> list:
    # KV Store sort syntax is "<field>:<1|-1>", not "-<field>"
    return kvstore.query(client, COLLECTION, sort="created_at:-1", limit=limit)


def clear(client: SplunkdClient) -> bool:
    return kvstore.clear(client, COLLECTION)


def prune(client: SplunkdClient, retention_days: int = RETENTION_DAYS) -> bool:
    """Delete records older than the retention window (bounds the collection)."""
    cutoff = int(time.time()) - retention_days * 86400
    return kvstore.delete_query(client, COLLECTION, {"created_at": {"$lt": cutoff}})


def stats(client: SplunkdClient) -> dict[str, Any]:
    rows = kvstore.query(client, COLLECTION, limit=5000)
    by_model: dict[str, int] = {}
    total_cost = 0.0
    for r in rows:
        by_model[r.get("model", "?")] = by_model.get(r.get("model", "?"), 0) + 1
        total_cost += float(r.get("cost_usd", 0) or 0)
    return {
        "count": len(rows),
        "total_cost_usd": round(total_cost, 4),
        "by_model": by_model,
    }
