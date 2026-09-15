"""Runtime guards for the critique endpoint: cache, rate limit, audit log.

Both cache and limiter are in-process — persistent handlers live across
requests, which is exactly the lifetime we want (and the demo pre-warm
mechanism: critique the scripted queries once before going on stage).

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
from collections import OrderedDict, deque
from typing import Any


def cache_key(spl: str, ruleset_version: str, models: list, context: dict | None = None) -> str:
    """Critique cache key. Context participates via its *stable* facts only
    (window, schedule, name, deep flag) — measured telemetry drifts hourly and
    would defeat the cache; slightly-stale telemetry in a cached critique is
    acceptable and bounded by KV-store retention."""
    parts = [" ".join(spl.split()), ruleset_version, ",".join(models)]
    if context:
        parts.append(
            "|".join(
                str(context.get(k, "")) for k in ("earliest", "latest", "cron", "name", "deep")
            )
        )
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


class LRUCache:
    def __init__(self, maxsize: int = 256) -> None:
        self.maxsize = maxsize
        self._data: OrderedDict = OrderedDict()

    def get(self, key: str) -> dict | None:
        if key not in self._data:
            return None
        self._data.move_to_end(key)
        return self._data[key]

    def put(self, key: str, value: dict) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)


class RateLimiter:
    """Sliding-window per-key limiter (default window: 60s)."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window = window_seconds
        self._hits: dict = {}

    def allow(self, key: str, limit: int, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        hits = self._hits.setdefault(key, deque())
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True


_audit_logger: logging.Logger | None = None


def _get_audit_logger() -> logging.Logger:
    global _audit_logger
    if _audit_logger is None:
        logger = logging.getLogger("spl_critic.audit")
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)  # lands in splunkd.log
            handler.setFormatter(logging.Formatter("spl_critic_audit %(message)s"))
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        _audit_logger = logger
    return _audit_logger


def audit(user: str, result: dict[str, Any], spl: str) -> None:
    """One JSON line per critique — compliance visibility, searchable in _internal."""
    _get_audit_logger().info(
        json.dumps(
            {
                "user": user,
                "verdict": result.get("verdict"),
                "codes": [r.get("code") for r in result.get("reasons", [])],
                "tier": result.get("tier"),
                "model": result.get("model"),
                "cost": (result.get("usage") or {}).get("cost"),
                "latency_ms": result.get("latency_ms"),
                "cached": result.get("cached", False),
                # context-budget instrumentation: prompt size grows with the
                # rule catalog; track it to know when retrieval must replace
                # stuff-everything (see docs/ROADMAP.md "Knowledge retrieval scaling")
                "prompt_tokens_est": (result.get("prompt") or {}).get("est_tokens"),
                "spl_sha256": hashlib.sha256(spl.encode()).hexdigest()[:16],
                "spl": spl[:500],
            },
            sort_keys=True,
        )
    )
