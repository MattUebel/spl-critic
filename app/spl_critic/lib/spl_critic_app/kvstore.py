"""Thin KV Store helpers over the splunkd REST client.

Collection data lives at storage/collections/data/<collection> (defined in
collections.conf, shipped in the app). Upserts go through batch_save so a
record with a supplied _key inserts or replaces. Every call is best-effort:
KV Store may be starting up or disabled, and persistence must never break a
critique — callers treat a False/None return as "not cached".

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
import urllib.parse

from spl_critic_app.splunkd_client import SplunkdClient

APP = "spl_critic"


def _base(collection: str) -> str:
    return f"/servicesNS/nobody/{APP}/storage/collections/data/{collection}"


def upsert(client: SplunkdClient, collection: str, records: list) -> bool:
    """Insert-or-replace records by their _key (batch_save)."""
    try:
        status, _ = client.post_json(f"{_base(collection)}/batch_save", records)
        return status in (200, 201)
    except Exception:
        return False


def insert(client: SplunkdClient, collection: str, record: dict) -> bool:
    """Append a record with an auto-generated _key (append-only history)."""
    try:
        status, _ = client.post_json(_base(collection), record)
        return status in (200, 201)
    except Exception:
        return False


def delete_query(client: SplunkdClient, collection: str, q: dict) -> bool:
    """Delete only records matching a query (leaves the rest)."""
    try:
        path = _base(collection) + "?query=" + urllib.parse.quote(json.dumps(q))
        status, _ = client.delete(path)
        return status == 200
    except Exception:
        return False


def get_one(client: SplunkdClient, collection: str, key: str) -> dict | None:
    try:
        status, body = client.get(f"{_base(collection)}/{urllib.parse.quote(key, safe='')}")
        if status != 200:
            return None
        rec = json.loads(body)
        return rec if isinstance(rec, dict) else None
    except Exception:
        return None


def query(
    client: SplunkdClient,
    collection: str,
    q: dict | None = None,
    sort: str = "",
    limit: int = 0,
    fields: str = "",
) -> list:
    params = []
    if q is not None:
        params.append("query=" + urllib.parse.quote(json.dumps(q)))
    if sort:
        params.append("sort=" + urllib.parse.quote(sort))
    if limit:
        params.append(f"limit={int(limit)}")
    if fields:  # comma-separated include list — scan big records cheaply
        params.append("fields=" + urllib.parse.quote(fields))
    path = _base(collection) + ("?" + "&".join(params) if params else "")
    try:
        status, body = client.get(path)
        if status != 200:
            return []
        rows = json.loads(body)
        return rows if isinstance(rows, list) else []
    except Exception:
        return []


def clear(client: SplunkdClient, collection: str) -> bool:
    try:
        status, _ = client.delete(_base(collection))
        return status == 200
    except Exception:
        return False


def available(client: SplunkdClient) -> bool:
    """True when KV Store is up (a query against the collection succeeds)."""
    try:
        status, _ = client.get(_base("spl_critic_inference") + "?limit=1")
        return status == 200
    except Exception:
        return False
