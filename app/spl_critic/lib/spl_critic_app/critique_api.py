"""REST handler for POST /services/spl_critic/critique.

The agent judges; nothing else does. When a model is configured the result
is the agent's verdict (single-shot, or tool-grounded with `deep: true`).
When no model can be reached the result is `status: unavailable` — no
verdict, no scores, no findings. The endpoint never 500s because a model is
down; it says so.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import contextlib
import json
import time
import urllib.parse
from typing import Any

from spl_critic_app import (
    agent_loop,
    app_config,
    audit,
    credentials,
    critic,
    custom_rules,
    deep,
    guards,
    inference_store,
    knowledge,
    prompts,
    splunkd_client,
)
from spl_critic_app.llm_backend import OpenRouterDriver
from spl_critic_app.splunk_compat import PersistentServerConnectionApplication

RATE_LIMIT_PER_MIN = 10  # agent calls per user per minute; over → unavailable


def _parse_request(in_string: str) -> tuple[dict, dict]:
    """(request dict, flattened args: query params + JSON body)."""
    try:
        request = json.loads(in_string) if in_string else {}
    except json.JSONDecodeError:
        return {}, {}

    args: dict[str, Any] = {}
    for key, value in request.get("query", []) or []:
        args[key] = value
    payload = request.get("payload")
    if payload:
        try:
            body = json.loads(payload)
            if isinstance(body, dict):
                args.update(body)
        except json.JSONDecodeError:
            pass
    return request, args


def _saved_search_context(client, name: str, bundle: dict) -> dict:
    """Schedule config + measured 30d telemetry for one saved search.

    Config comes from the merged saved/searches entry; telemetry from the
    audit tier's scheduler (_internal) and history (_audit) oneshots. An
    unset dispatch.earliest_time means all time in savedsearches.conf, so it
    normalizes to the explicit "0" marker — 'unknown' is not a possibility
    for a saved search the way it is for pasted SPL.
    """
    ctx: dict[str, Any] = {"name": name}
    status, doc = client.get_json(
        "/servicesNS/-/-/saved/searches/"
        + urllib.parse.quote(name, safe="")
        + "?output_mode=json"
    )
    if status == 200:
        content = splunkd_client.first_entry_content(doc)
        ctx["earliest"] = str(content.get("dispatch.earliest_time", "") or "").strip() or "0"
        ctx["latest"] = str(content.get("dispatch.latest_time", "") or "").strip() or "now"
        cron = str(content.get("cron_schedule", "") or "")
        if cron:
            ctx["cron"] = cron
            ctx["runs_per_day"] = audit.cron_runs_per_day(cron)
    telemetry: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        sched = audit.scheduler_stats(client).get(name)
        if sched:
            telemetry.update(
                {f"sched_{k}": v for k, v in sched.items() if not isinstance(v, (dict, list))}
            )
    with contextlib.suppress(Exception):
        hist = audit.history_stats(client, bundle).get(name)
        if hist:
            telemetry.update(
                {f"audit_{k}": v for k, v in hist.items() if not isinstance(v, (dict, list))}
            )
    if telemetry:
        ctx["telemetry"] = telemetry
    return ctx


def _build_context(client, args: dict, bundle: dict) -> dict | None:
    """Assemble the critique context from request args (window, saved search)."""
    context: dict[str, Any] = {}
    saved = (str(args.get("saved_search") or "")).strip()
    if saved and client is not None:
        with contextlib.suppress(Exception):
            context.update(_saved_search_context(client, saved, bundle))
        context.setdefault("name", saved)
    # explicit window params override the saved-search config
    earliest = (str(args.get("earliest") or "")).strip()
    latest = (str(args.get("latest") or "")).strip()
    if earliest:
        context["earliest"] = earliest
        context["latest"] = latest or "now"
    elif latest:
        context["latest"] = latest
    return context or None


class CritiqueHandler(PersistentServerConnectionApplication):
    """POST {spl, earliest?, latest?, saved_search?, deep?} →
    the agent's critique JSON, or an honest `unavailable`."""

    # class-level: shared across requests for the life of the handler process
    _cache = guards.LRUCache(maxsize=256)
    _limiter = guards.RateLimiter()
    _last_prune = 0.0  # epoch of last cache prune; hourly at most

    def __init__(self, command_line: str = "", command_arg: str = "") -> None:  # noqa: ARG002
        super().__init__()
        self._bundle: dict | None = None  # tests inject; splunkd lazy-loads
        self._fragments: dict | None = None
        # test seams: replace to fake splunkd / the LLM driver
        self._client_factory = splunkd_client.from_request
        self._driver_factory = OpenRouterDriver

    def _get_bundle(self) -> dict:
        if self._bundle is None:
            self._bundle = knowledge.load_bundle()
        return self._bundle

    def _get_fragments(self) -> dict:
        if self._fragments is None:
            self._fragments = knowledge.load_fragments()
        return self._fragments

    def _effective_bundle(self, client) -> dict:
        """Compiled bundle + this environment's custom rules and guidance."""
        bundle = self._get_bundle()
        if client is None:
            return bundle
        try:
            custom, _errors = custom_rules.fetch(client)
            guidance = app_config.extra_guidance(client)
            return custom_rules.effective_bundle(bundle, custom, guidance)
        except Exception:
            return bundle  # environment layer is enrichment, never a blocker

    def _maybe_prune(self, client) -> None:
        """Prune the inference cache at most hourly — bounds the collection
        without adding a delete to every critique."""
        now = time.time()
        if now - CritiqueHandler._last_prune < 3600:
            return
        CritiqueHandler._last_prune = now
        with contextlib.suppress(Exception):
            inference_store.prune(client)

    def _build_driver(self, client) -> Any | None:
        """Driver when the model tier is fully configured, else None."""
        try:
            if client is None:
                return None
            settings = app_config.llm_settings(client)
            if not settings["enabled"] or not settings["models"]:
                return None
            api_key = credentials.get_api_key(client)
            if not api_key:
                return None
            return self._driver_factory(
                api_key,
                settings["models"],
                timeout=settings["timeout"],
                reasoning=settings["reasoning"],
            )
        except Exception:
            return None  # any splunkd hiccup → unavailable, never an error

    def handle(self, in_string: str) -> dict[str, Any]:
        request, args = _parse_request(in_string)

        spl = (args.get("spl") or "").strip()
        if not spl:
            return {"status": 400, "payload": {"error": "missing required parameter: spl"}}

        try:
            client = self._client_factory(request)
        except Exception:
            client = None
        bundle = self._effective_bundle(client)

        user = (request.get("session", {}) or {}).get("user", "unknown")
        driver = self._build_driver(client)
        context = _build_context(client, args, bundle)
        deep_requested = bool(args.get("deep"))

        if driver is None:
            result = critic.unavailable(
                critic.indicators(spl, bundle, context), bundle, "no_model"
            )
        else:
            # the deep (agent) critique is tool-grounded — a different result
            # than the single-shot, so it caches under its own key
            key_context = dict(context or {})
            if deep_requested:
                key_context["deep"] = "1"
            key = guards.cache_key(
                spl,
                f"{bundle.get('ruleset_version', '')}/p{prompts.PROMPT_VERSION}",
                driver.models,
                key_context or None,
            )
            cached = self._cache.get(key)
            persisted = None if cached is not None else inference_store.get_cached(client, key)
            if cached is not None:
                result = dict(cached)
                result["cached"] = True
            elif persisted is not None and inference_store.result_from_record(persisted):
                # persistent hit: survives restart; also warms the in-process cache
                result = inference_store.result_from_record(persisted)
                self._cache.put(key, result)
                result["cached"] = True
            elif not self._limiter.allow(user, RATE_LIMIT_PER_MIN):
                result = critic.unavailable(
                    critic.indicators(spl, bundle, context), bundle, "rate_limited"
                )
            else:
                if deep_requested and client is not None:
                    # the agent loop investigates with tools before judging
                    result = agent_loop.critique_deep(
                        client, spl, bundle, self._get_fragments(), driver, context=context
                    )
                else:
                    result = critic.critique_with_llm(
                        spl, bundle, self._get_fragments(), driver, context=context
                    )
                if result.get("status") == "analyzed":  # only cache real judgments
                    self._cache.put(key, result)
                    with contextlib.suppress(Exception):
                        inference_store.store(
                            client,
                            inference_store.build_record(
                                key, spl, result, user=user, source="critique"
                            ),
                        )
                        self._maybe_prune(client)

        # deep analysis when the agent did not run the search itself: guarded
        # execution still turns "might be expensive" into measured evidence
        if deep_requested and client is not None and "evidence" not in result:
            try:
                result["evidence"] = deep.run_guarded(client, spl, bundle, context=context)
            except Exception as e:
                result["evidence"] = {"error": f"deep analysis failed: {e}"}
        if result.get("suggested_spl") and client is not None:
            # best-effort; an absent key means "not checked"
            with contextlib.suppress(Exception):
                result["rewrite_valid"] = deep.validate_rewrite(client, result["suggested_spl"])

        result["user"] = user
        guards.audit(user, result, spl)
        return {"status": 200, "payload": result}
