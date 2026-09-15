"""Health endpoint — the walking skeleton for the REST layer.

Proves the full path works: packaged app -> restmap.conf -> persistent
handler -> vendored lib package -> JSON response with the app version.
"""

from __future__ import annotations

import json
from typing import Any

from spl_critic_app import APP_NAME, __version__
from spl_critic_app.splunk_compat import PersistentServerConnectionApplication


class HealthHandler(PersistentServerConnectionApplication):
    """REST handler for GET /services/spl_critic/health."""

    def __init__(self, command_line: str = "", command_arg: str = "") -> None:  # noqa: ARG002
        super().__init__()

    def handle(self, in_string: str) -> dict[str, Any]:
        try:
            args = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            args = {}

        return {
            "status": 200,
            "payload": {
                "status": "healthy",
                "app": APP_NAME,
                "version": __version__,
                "user": args.get("session", {}).get("user", "unknown"),
            },
        }
