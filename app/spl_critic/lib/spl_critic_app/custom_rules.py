"""Environment-local rules and prompt guidance, layered at request time.

Admins extend the shipped knowledge without rebuilding the app:
  - spl_critic_rules.conf — one stanza per custom detector (regex-based),
    managed via /services/spl_critic/rules or any conf mechanism
  - spl_critic.conf [prompt] extra_guidance — free text appended to the
    LLM system prompt (index sizes, naming conventions, local policy)

Custom rules flow through the same detector/policy/prompt machinery as
compiled rules; the effective ruleset version changes when they do, so the
critique cache can never serve stale verdicts.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from spl_critic_app.splunkd_client import SplunkdClient

RULES_CONF = "/servicesNS/nobody/spl_critic/configs/conf-spl_critic_rules"
CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
SEVERITIES = ("info", "low", "medium", "high", "critical")
_DEFAULT_WEIGHTS = {
    "info": (0, 0),
    "low": (20, 30),
    "medium": (40, 55),
    "high": (70, 75),
    "critical": (90, 90),
}


def validate(stanza: str, content: dict) -> tuple[dict, list]:
    """(rule record, errors). Record is None-equivalent ({}) when invalid."""
    errors = []
    rule_id = stanza.strip().upper()
    if not CODE_RE.match(rule_id):
        errors.append(f"{stanza}: id must be UPPER_SNAKE with an underscore (e.g. LOCAL_X)")
    severity = str(content.get("severity", "")).strip().lower()
    if severity not in SEVERITIES:
        errors.append(f"{stanza}: severity must be one of {list(SEVERITIES)}")
    pattern = str(content.get("regex", "") or "")
    if pattern:  # optional: no regex → AI-judgment rule (prompt vocabulary only)
        try:
            re.compile(pattern)
        except re.error as e:
            errors.append(f"{stanza}: bad regex: {e}")
    if errors:
        return {}, errors

    scope = str(content.get("scope", "pipeline")).strip().lower()
    if scope not in ("retrieval", "pipeline"):
        scope = "pipeline"
    default_risk, default_cost = _DEFAULT_WEIGHTS[severity]

    def _weight(key, default):
        try:
            return max(0, min(100, int(content.get(key, default))))
        except (TypeError, ValueError):
            return default

    # display name lives under 'label' in conf ('name' is the stanza id in the
    # conf REST API and would hijack stanza creation); accept 'name' for
    # hand-authored conf files
    name = str(content.get("label") or content.get("name") or rule_id)
    cost_rationale = str(content.get("cost_rationale", "") or "Local policy rule.")
    risk_rationale = str(content.get("risk_rationale", "") or "Local policy rule.")
    rewrite = str(content.get("canonical_rewrite", "") or "See local guidance.")
    rule = {
        "id": rule_id,
        "name": name,
        "kind": "detector",
        "category": "custom",
        "severity": severity,
        "risk_weight": _weight("risk_weight", default_risk),
        "cost_weight": _weight("cost_weight", default_cost),
        "detection_signals": {
            "regexes": [{"pattern": pattern, "scope": scope}] if pattern else [],
            "pipeline_checks": [],
        },
        "cost_rationale": cost_rationale,
        "risk_rationale": risk_rationale,
        "canonical_rewrite": rewrite,
        "doc_citation": str(content.get("doc_citation", "") or "local policy"),
        "job_inspector_confirmation": "",
        "aliases": [],
        # prompt fragment, same shape the compiler emits for shipped rules
        "fragment": (
            f"{rule_id} ({name}; severity {severity}; "
            + (
                "LOCAL RULE"
                if pattern
                else "LOCAL AI-JUDGMENT RULE — no static detector, apply your own reading"
            )
            + "): "
            f"{cost_rationale} Risk: {risk_rationale} Fix: {rewrite}"
        ),
    }
    return rule, []


def fetch(client: SplunkdClient) -> tuple[list, list]:
    """(valid custom rules, validation errors) from spl_critic_rules.conf."""
    status, doc = client.get_json(f"{RULES_CONF}?count=0")
    if status != 200:
        return [], []
    rules, errors = [], []
    for entry in doc.get("entry", []):
        content = entry.get("content", {}) or {}
        if str(content.get("enabled", "1")) in ("0", "false", "False"):
            continue
        if str(content.get("disabled", "0")) in ("1", "true", "True"):
            continue
        rule, errs = validate(entry.get("name", ""), content)
        errors.extend(errs)
        if rule:
            rules.append(rule)
    return sorted(rules, key=lambda r: r["id"]), errors


def effective_bundle(bundle: dict, custom: list, extra_guidance: str = "") -> dict[str, Any]:
    """Compiled bundle + environment layer. Returns the bundle unchanged when
    there is nothing local, so the common path stays zero-copy."""
    if not custom and not extra_guidance:
        return bundle
    # shipped rule ids win on collision — local rules cannot shadow the catalog
    shipped = {r["id"] for r in bundle["rules"]}
    for r in bundle["rules"]:
        shipped.update(r.get("aliases", []))
    merged = list(bundle["rules"]) + [r for r in custom if r["id"] not in shipped]

    local_hash = hashlib.sha256(
        json.dumps({"rules": merged[len(bundle["rules"]) :], "guidance": extra_guidance},
                   sort_keys=True).encode()
    ).hexdigest()[:8]
    eff = dict(bundle)
    eff["rules"] = merged
    eff["ruleset_version"] = f"{bundle.get('ruleset_version', '')}+{local_hash}"
    eff["extra_guidance"] = extra_guidance
    return eff
