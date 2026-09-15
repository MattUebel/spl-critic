"""REST handler for /services/spl_critic/inference — cache history utilities.

GET                    → recent inference history + aggregate stats
POST {clear: true}     → wipe the inference cache/history

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
from typing import Any

from spl_critic_app import inference_store, kvstore, splunkd_client
from spl_critic_app.splunk_compat import PersistentServerConnectionApplication

_FIELDS = (
    "search_name", "app", "source", "model", "verdict",
    "risk_score", "cost_score", "cost_usd", "latency_ms", "redactions",
    "created_at",
)


class InferenceHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line: str = "", command_arg: str = "") -> None:  # noqa: ARG002
        super().__init__()
        self._client_factory = splunkd_client.from_request  # test seam

    def handle(self, in_string: str) -> dict[str, Any]:
        try:
            request = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            request = {}
        client = self._client_factory(request)
        if client is None:
            return {"status": 401, "payload": {"error": "no splunkd session"}}

        if str(request.get("method", "GET")).upper() == "POST":
            try:
                body = json.loads(request.get("payload") or "{}")
            except json.JSONDecodeError:
                body = {}
            if body.get("clear"):
                return {"status": 200, "payload": {"cleared": inference_store.clear(client)}}
            if body.get("prune"):
                days = int(body.get("retention_days", inference_store.RETENTION_DAYS))
                return {"status": 200, "payload": {"pruned": inference_store.prune(client, days)}}
            return {
                "status": 400,
                "payload": {"error": "nothing to do — send {clear: true} or {prune: true}"},
            }

        if not kvstore.available(client):
            return {"status": 200, "payload": {"available": False, "history": [], "stats": {}}}
        history = [
            {k: r.get(k) for k in _FIELDS}
            for r in inference_store.history(client, limit=100)
        ]
        return {
            "status": 200,
            "payload": {
                "available": True,
                "history": history,
                "stats": inference_store.stats(client),
            },
        }
