"""REST handler for /services/spl_critic/rules — environment-local rules.

GET  → shipped-rule count + this environment's custom rules (with validation
       state), effective ruleset version
POST {id, name, severity, regex, ...} → validate + upsert a custom rule
POST {id, delete: true}               → remove a custom rule

Rules are stored in local/spl_critic_rules.conf via splunkd, so they survive
app upgrades and never require a rebuild.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
from typing import Any

from spl_critic_app import app_config, custom_rules, knowledge, splunkd_client
from spl_critic_app.splunk_compat import PersistentServerConnectionApplication

# 'label' not 'name': in the conf REST API, 'name' is the stanza id — sending
# it as a field hijacks stanza creation (found by live testing).
_WRITABLE_FIELDS = (
    "label",
    "severity",
    "regex",
    "scope",
    "risk_weight",
    "cost_weight",
    "cost_rationale",
    "risk_rationale",
    "canonical_rewrite",
    "doc_citation",
    "enabled",
)


class RulesHandler(PersistentServerConnectionApplication):
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

        custom, errors = custom_rules.fetch(client)
        bundle = self._get_bundle()
        effective = custom_rules.effective_bundle(
            bundle, custom, app_config.extra_guidance(client)
        )
        return {
            "status": 200,
            "payload": {
                "shipped_rules": len(bundle["rules"]),
                "shipped": [
                    {
                        k: r[k]
                        for k in (
                            "id", "name", "kind", "category", "severity",
                            "risk_weight", "cost_weight", "cost_rationale",
                            "risk_rationale", "canonical_rewrite", "doc_citation",
                        )
                    }
                    | {"detection": r.get("detection_signals", {})}
                    for r in bundle["rules"]
                ],
                "custom_rules": [
                    {k: r[k] for k in ("id", "name", "severity", "risk_weight", "cost_weight")}
                    | {"regex": r["detection_signals"]["regexes"][0]["pattern"]}
                    for r in custom
                ],
                "validation_errors": errors,
                "ruleset_version": effective.get("ruleset_version", ""),
            },
        }

    def _handle_post(self, request: dict, client) -> dict[str, Any]:
        try:
            body = json.loads(request.get("payload") or "{}")
        except json.JSONDecodeError:
            body = {}
        rule_id = str(body.get("id", "")).strip().upper()
        if not rule_id:
            return {"status": 400, "payload": {"error": "missing required field: id"}}
        if "name" in body and "label" not in body:
            body["label"] = body["name"]  # API convenience alias
        stanza_path = f"{custom_rules.RULES_CONF}/{rule_id}"

        if body.get("delete"):
            status, resp = client.delete(stanza_path)
            if status not in (200, 201):
                return {"status": 502, "payload": {"error": f"delete failed ({status})"}}
            return {"status": 200, "payload": {"deleted": rule_id}}

        rule, errors = custom_rules.validate(rule_id, body)
        if errors:
            return {"status": 400, "payload": {"errors": errors}}
        shipped = {r["id"] for r in self._get_bundle()["rules"]}
        if rule_id in shipped:
            return {
                "status": 400,
                "payload": {"error": f"{rule_id} is a shipped catalog code — pick a LOCAL_* id"},
            }

        fields = {k: str(body[k]) for k in _WRITABLE_FIELDS if k in body}
        status, resp = client.post(stanza_path, fields)
        if status == 404:
            status, resp = client.post(custom_rules.RULES_CONF, {"name": rule_id} | fields)
        if status not in (200, 201):
            return {"status": 502, "payload": {"error": f"write failed ({status}): {resp[:200]!r}"}}
        return {"status": 200, "payload": {"stored": rule_id, "rule": rule}}
