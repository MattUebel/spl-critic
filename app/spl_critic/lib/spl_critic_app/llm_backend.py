"""LLM backend abstraction: one interface, pluggable drivers.

Drivers implement complete_json(messages, schema) -> LLMResponse. OpenRouter
is the first driver; a Splunk-hosted-inference driver and a local Ollama
driver slot in behind the same interface later (offline demo fallback).

Engineering for demo reliability:
  - structured outputs (response_format: json_schema, strict) — no prose parsing
  - model fallback list (OpenRouter `models:` routing)
  - temperature 0, one retry on transport/5xx/parse errors
  - usage + cost captured on every call (feeds the eval harness and audit log)

Stdlib only (urllib) — vendored into the app; runs on Splunk Python 3.9.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

DEFAULT_TIMEOUT = 60
ATTRIBUTION_REFERER = "https://github.com/mattuebel/spl-critic"
ATTRIBUTION_TITLE = "SPL Critic"


class LLMError(Exception):
    """The backend could not produce a valid structured response."""


@dataclass
class LLMResponse:
    content: dict  # parsed JSON matching the requested schema
    model: str  # the model that actually served the call
    usage: dict = field(default_factory=dict)  # prompt/completion tokens, cost
    latency_ms: int = 0


class OpenRouterDriver:
    """OpenRouter chat completions with strict JSON-schema output."""

    def __init__(
        self,
        api_key: str,
        models: list,
        base_url: str = "https://openrouter.ai/api/v1",
        timeout: int = DEFAULT_TIMEOUT,
        reasoning: bool = False,
    ) -> None:
        if not models:
            raise ValueError("at least one model id is required")
        self.api_key = api_key
        self.models = list(models)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.reasoning = reasoning

    def build_request_body(self, messages: list, schema: dict) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.models[0],
            "messages": messages,
            "temperature": 0,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "spl_critique", "strict": True, "schema": schema},
            },
            "usage": {"include": True},
        }
        if not self.reasoning:
            # hybrid models burn most of their latency on reasoning tokens
            # (measured: 55 s for a critique) — off by default, conf-togglable
            body["reasoning"] = {"enabled": False}
        if len(self.models) > 1:
            body["models"] = self.models  # OpenRouter fallback routing
        return body

    def _post(self, body: dict) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": ATTRIBUTION_REFERER,
                "X-Title": ATTRIBUTION_TITLE,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    def complete_tools(self, messages: list, tools: list) -> tuple[dict, dict]:
        """One tools-protocol turn: (assistant message dict, usage dict).

        The assistant message either carries `tool_calls` (the caller executes
        them and appends role:"tool" results) or plain content (the model is
        done investigating). No response_format here — several providers
        reject tools + json_schema in the same request; the caller finishes
        with a complete_json call once the investigation ends.
        """
        body: dict[str, Any] = {
            "model": self.models[0],
            "messages": messages,
            "temperature": 0,
            "tools": tools,
            "usage": {"include": True},
        }
        if not self.reasoning:
            body["reasoning"] = {"enabled": False}
        if len(self.models) > 1:
            body["models"] = self.models
        last_error: Exception = LLMError("no attempt made")
        for attempt in (1, 2):
            try:
                raw = self._post(body)
                return raw["choices"][0]["message"], raw.get("usage", {}) or {}
            except urllib.error.HTTPError as e:
                detail = e.read()[:500].decode(errors="replace")
                last_error = LLMError(f"HTTP {e.code} from OpenRouter: {detail}")
                if e.code < 500 and e.code != 429:
                    break
            except (urllib.error.URLError, OSError, TimeoutError) as e:
                last_error = LLMError(f"transport error: {e}")
            except (KeyError, IndexError, ValueError, TypeError) as e:
                last_error = LLMError(f"malformed response: {e}")
            if attempt == 1:
                time.sleep(1)
        raise last_error

    def complete_json(self, messages: list, schema: dict) -> LLMResponse:
        body = self.build_request_body(messages, schema)
        last_error: Exception = LLMError("no attempt made")
        for attempt in (1, 2):  # one retry, per the demo-reliability rule
            start = time.time()
            try:
                raw = self._post(body)
                content = raw["choices"][0]["message"]["content"]
                return LLMResponse(
                    content=json.loads(content),
                    model=raw.get("model", self.models[0]),
                    usage=raw.get("usage", {}) or {},
                    latency_ms=int((time.time() - start) * 1000),
                )
            except urllib.error.HTTPError as e:
                detail = e.read()[:500].decode(errors="replace")
                last_error = LLMError(f"HTTP {e.code} from OpenRouter: {detail}")
                if e.code < 500 and e.code != 429:
                    break  # 4xx (except rate limit) will not improve on retry
            except (urllib.error.URLError, OSError, TimeoutError) as e:
                last_error = LLMError(f"transport error: {e}")
            except (KeyError, IndexError, ValueError, TypeError) as e:
                # includes content=None from providers that route structured
                # output into other fields — malformed for our purposes
                last_error = LLMError(f"malformed response: {e}")
            if attempt == 1:
                time.sleep(1)
        raise last_error
