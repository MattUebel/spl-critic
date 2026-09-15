"""Read app settings through splunkd's conf layering (configs/conf-*).

splunkd merges default/ and local/ for us — no hand-parsed conf files
(predecessor mistake #3).

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

from typing import Any

from spl_critic_app.splunkd_client import SplunkdClient, first_entry_content

_CONF = "/servicesNS/nobody/spl_critic/configs/conf-spl_critic"
_LLM_STANZA = _CONF + "/llm"
_PROMPT_STANZA = _CONF + "/prompt"

_DEFAULTS = {
    "enabled": True,
    "models": [],
    "timeout": 60,
    "reasoning": False,
}


def llm_settings(client: SplunkdClient) -> dict[str, Any]:
    status, doc = client.get_json(_LLM_STANZA)
    if status != 200:
        return dict(_DEFAULTS)
    content = first_entry_content(doc)
    models = [m.strip() for m in str(content.get("models", "")).split(",") if m.strip()]
    return {
        "enabled": str(content.get("enabled", "1")) in ("1", "true", "True"),
        "models": models,
        "timeout": int(content.get("timeout", 60) or 60),
        "reasoning": str(content.get("reasoning", "0")) in ("1", "true", "True"),
    }


def extra_guidance(client: SplunkdClient) -> str:
    """Admin-provided text appended to the LLM system prompt ([prompt] stanza)."""
    status, doc = client.get_json(_PROMPT_STANZA)
    if status != 200:
        return ""
    return str(first_entry_content(doc).get("extra_guidance", "") or "").strip()


def write_setting(client: SplunkdClient, stanza: str, key: str, value: str) -> None:
    """Write one key into local/spl_critic.conf via splunkd (layered override)."""
    status, body = client.post(f"{_CONF}/{stanza}", {key: value})
    if status == 404:
        status, body = client.post(_CONF, {"name": stanza, key: value})
    if status not in (200, 201):
        raise RuntimeError(f"writing [{stanza}] {key} failed ({status}): {body[:200]!r}")
