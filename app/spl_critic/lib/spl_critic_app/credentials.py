"""OpenRouter API key in Splunk's encrypted credential store.

storage/passwords, realm 'spl_critic' — never in conf files, never in
local/. (The predecessor app stored it cleartext in local/; this module is
the fix.)

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

from spl_critic_app.splunkd_client import SplunkdClient, first_entry_content

REALM = "spl_critic"
KEY_NAME = "openrouter_api_key"
_BASE = "/servicesNS/nobody/spl_critic/storage/passwords"
# storage/passwords entry ids are '<realm>:<name>:' with ':' URL-encoded
_ENTRY = f"{_BASE}/{REALM}%3A{KEY_NAME}%3A"


def get_api_key(client: SplunkdClient) -> str | None:
    status, doc = client.get_json(_ENTRY)
    if status != 200:
        return None
    return first_entry_content(doc).get("clear_password") or None


def store_api_key(client: SplunkdClient, value: str) -> None:
    status, body = client.post(_ENTRY, {"password": value})
    if status == 404:
        status, body = client.post(_BASE, {"name": KEY_NAME, "realm": REALM, "password": value})
    if status not in (200, 201):
        raise RuntimeError(f"storing credential failed ({status}): {body[:200]!r}")
