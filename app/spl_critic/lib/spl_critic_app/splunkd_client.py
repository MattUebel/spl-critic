"""Minimal splunkd REST client for use inside persistent handlers.

Persistent handlers receive a session token and the local splunkd URI in
every request — that is all we need to reach storage/passwords and conf
endpoints. No SDK dependency; stdlib urllib against localhost.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class SplunkdClient:
    def __init__(self, rest_uri: str, session_key: str, timeout: int = 10) -> None:
        self.rest_uri = rest_uri.rstrip("/")
        self.session_key = session_key
        self.timeout = timeout
        # splunkd on localhost uses a self-signed cert
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _request(
        self,
        path: str,
        data: dict | None = None,
        method: str | None = None,
        json_body: Any = None,
    ) -> tuple[int, bytes]:
        url = self.rest_uri + path
        headers = {"Authorization": f"Splunk {self.session_key}"}
        if json_body is not None:  # KV Store needs a JSON body, not form-encoded
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        else:
            body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def get(self, path: str) -> tuple[int, bytes]:
        """Raw GET — no output_mode appended (KV Store returns JSON natively)."""
        return self._request(path)

    def get_json(self, path: str) -> tuple[int, dict]:
        sep = "&" if "?" in path else "?"
        status, body = self._request(f"{path}{sep}output_mode=json")
        try:
            return status, json.loads(body)
        except (ValueError, TypeError):
            return status, {}

    def post(self, path: str, data: dict) -> tuple[int, bytes]:
        return self._request(path, data=data)

    def post_json(self, path: str, obj: Any) -> tuple[int, bytes]:
        return self._request(path, json_body=obj, method="POST")

    def delete(self, path: str) -> tuple[int, bytes]:
        return self._request(path, method="DELETE")


def from_request(request: dict) -> SplunkdClient | None:
    """Build a client from a persistent-handler request dict, if possible."""
    session = request.get("session", {}) or {}
    token = session.get("authtoken", "")
    rest_uri = (request.get("server", {}) or {}).get("rest_uri", "https://127.0.0.1:8089")
    if not token:
        return None
    return SplunkdClient(rest_uri, token)


def first_entry_content(doc: dict) -> dict[str, Any]:
    """The content dict of the first entry in a splunkd JSON response."""
    entries = doc.get("entry", [])
    if entries:
        return entries[0].get("content", {}) or {}
    return {}
