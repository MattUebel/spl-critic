"""REST handler for /services/spl_critic/config.

GET  → current LLM tier status (configured? which models? ruleset version)
POST {openrouter_api_key} → store the key in the encrypted credential store

The key never appears in a response and never touches a conf file.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
from typing import Any

from spl_critic_app import app_config, credentials, custom_rules, knowledge, splunkd_client
from spl_critic_app.splunk_compat import PersistentServerConnectionApplication


class ConfigHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line: str = "", command_arg: str = "") -> None:  # noqa: ARG002
        super().__init__()
        self._bundle: dict | None = None
        self._client_factory = splunkd_client.from_request  # test seam

    def _get_bundle(self) -> dict:
        if self._bundle is None:
            self._bundle = knowledge.load_bundle()
        return self._bundle

    def handle(self, in_string: str) -> dict[str, Any]:
        try:
            request = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            request = {}

        client = self._client_factory(request)
        if client is None:
            return {"status": 401, "payload": {"error": "no splunkd session"}}

        if str(request.get("method", "GET")).upper() == "POST":
            return self._handle_post(request, client)

        settings = app_config.llm_settings(client)
        bundle = self._get_bundle()
        guidance = app_config.extra_guidance(client)
        custom, _errors = custom_rules.fetch(client)
        return {
            "status": 200,
            "payload": {
                "llm_enabled": settings["enabled"],
                "llm_configured": bool(credentials.get_api_key(client)),
                "models": settings["models"],
                "ruleset_version": custom_rules.effective_bundle(bundle, custom, guidance).get(
                    "ruleset_version", ""
                ),
                "custom_rules": len(custom),
                "extra_guidance": guidance,
                "reasoning": settings["reasoning"],
            },
        }

    def _handle_post(self, request: dict, client) -> dict[str, Any]:
        """Accepts any of: openrouter_api_key, models, extra_guidance."""
        try:
            body = json.loads(request.get("payload") or "{}")
        except json.JSONDecodeError:
            body = {}

        stored = []
        try:
            if (body.get("openrouter_api_key") or "").strip():
                credentials.store_api_key(client, body["openrouter_api_key"].strip())
                stored.append("openrouter_api_key")
            if "models" in body:
                models = body["models"]
                if isinstance(models, list):
                    models = ",".join(str(m).strip() for m in models)
                app_config.write_setting(client, "llm", "models", str(models))
                stored.append("models")
            if "extra_guidance" in body:
                app_config.write_setting(
                    client, "prompt", "extra_guidance", str(body["extra_guidance"])
                )
                stored.append("extra_guidance")
            if "reasoning" in body:
                app_config.write_setting(
                    client, "llm", "reasoning", "1" if body["reasoning"] else "0"
                )
                stored.append("reasoning")
        except RuntimeError as e:
            return {"status": 502, "payload": {"error": str(e), "stored": stored}}

        if not stored:
            return {
                "status": 400,
                "payload": {
                    "error": "nothing to store — send openrouter_api_key, models, "
                    "extra_guidance, and/or reasoning"
                },
            }
        return {"status": 200, "payload": {"stored": stored}}
