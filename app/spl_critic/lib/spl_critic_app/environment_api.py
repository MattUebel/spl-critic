"""REST handler for GET /services/spl_critic/environment — the index scan."""

from __future__ import annotations

import json
from typing import Any

from spl_critic_app import environment, splunkd_client
from spl_critic_app.splunk_compat import PersistentServerConnectionApplication


class EnvironmentHandler(PersistentServerConnectionApplication):
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
        return {"status": 200, "payload": environment.scan(client)}
