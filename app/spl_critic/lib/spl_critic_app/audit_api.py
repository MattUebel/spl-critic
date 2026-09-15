"""REST handler for POST /services/spl_critic/audit.

Gathers the facts about every saved search the caller can see (all apps),
then attaches the agent's analysis per row: cached analyses always (instant
when the portfolio has been judged before), fresh ones when `llm: true`
within a per-request time budget the client loops over. Rows the agent has
not judged yet are PENDING — never scored by a rulebook.

Also inventories dashboards (refresh cadence = invocation-owned cost) and,
on request, has the agent judge a dashboard's searches.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
from typing import Any

from spl_critic_app import (
    app_config,
    audit,
    audit_store,
    credentials,
    critic,
    custom_rules,
    dashboards,
    environment,
    guards,
    inference_store,
    knowledge,
    prompts,
    splunkd_client,
)
from spl_critic_app.llm_backend import OpenRouterDriver
from spl_critic_app.splunk_compat import PersistentServerConnectionApplication

_LLM_ENRICH_CAP = 8  # default top-N when no explicit target is given
_ENRICH_TIME_BUDGET_S = 110  # per-request budget; the client loops until done
_RUN_LIST_LIMIT = 20  # default page for the "previous runs" list
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # client-supplied continuation ids
_VERDICT_RANK = {"blocked": 3, "warn": 2, "approved": 1}


def _row_context(row: dict) -> dict:
    """The audit row's facts as critique context: the schedule and window from
    config, the measured 30d telemetry from the logs, and the gathered flags.
    This is what 'the agent evaluates search histories' means for a scheduled
    search — the row already carries them; the agent sees them."""
    ctx: dict[str, Any] = {"name": row.get("name", "")}
    if row.get("scheduled"):
        ctx["earliest"] = str(row.get("dispatch_earliest", "") or "").strip() or "0"
        ctx["latest"] = str(row.get("dispatch_latest", "") or "").strip() or "now"
        if row.get("cron_schedule"):
            ctx["cron"] = row["cron_schedule"]
            ctx["runs_per_day"] = row.get("runs_per_day")
    telemetry: dict[str, Any] = {}
    for prefix, blob in (("sched", row.get("scheduler")), ("audit", row.get("history"))):
        if isinstance(blob, dict):
            telemetry.update(
                {f"{prefix}_{k}": v for k, v in blob.items() if not isinstance(v, (dict, list))}
            )
    if telemetry:
        ctx["telemetry"] = telemetry
    facts: dict[str, Any] = {}
    if row.get("flags"):
        facts["flags"] = ",".join(row["flags"])
    if row.get("phantom_indexes"):
        facts["missing_indexes"] = ",".join(row["phantom_indexes"])
    if row.get("alert_payload_cap") is not None:
        facts["alert_payload_cap"] = row["alert_payload_cap"]
    if row.get("disabled"):
        facts["disabled"] = "yes"
    if not row.get("scheduled"):
        facts["scheduled"] = "no (ad-hoc saved search)"
    if facts:
        ctx["facts"] = facts
    return ctx


def _dashboard_context(item: dict, search: dict) -> dict:
    ctx: dict[str, Any] = {
        "kind": "dashboard",
        "name": item.get("label") or item.get("name", ""),
        "refresh_s": search.get("refresh_s"),
        "refresh_type": search.get("refresh_type", ""),
    }
    earliest = str(search.get("earliest", "") or "").strip()
    if earliest:
        ctx["earliest"] = earliest
        ctx["latest"] = str(search.get("latest", "") or "").strip() or "now"
    return ctx


def analysis_block(full: dict, runs_per_day: float = 0.0) -> dict:
    """The per-row analysis carried in audit rows and stored runs: the agent's
    judgment, trimmed to what the Auditor renders."""
    verdict = full.get("verdict")
    return {
        "verdict": verdict,
        "disposition": full.get("disposition"),
        "risk_score": full.get("risk_score", 0),
        "cost_score": full.get("cost_score", 0),
        "reasons": full.get("reasons", []),
        "summary": full.get("summary", ""),
        "suggested_spl": full.get("suggested_spl"),
        "model": full.get("model"),
        "cached": bool(full.get("cached")),
        "llm_error": full.get("llm_error"),
        # the Act 6 ranking: how bad (the agent's cost score) x how often
        "rank_score": round(float(full.get("cost_score", 0) or 0) * max(runs_per_day, 1.0), 1)
        if verdict
        else 0.0,
    }


# The scheduler health read: the numbers stay measured; the agent writes the
# remediation memo over them and over its own per-search verdicts.
_HEALTH_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "priorities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "recommendation": {"type": "string"},
                },
                "required": ["target", "recommendation"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "priorities"],
    "additionalProperties": False,
}


def _health_messages(result: dict) -> list:
    judged = [r for r in result["results"] if (r.get("analysis") or {}).get("verdict")]
    top = [
        {
            "name": r["name"],
            "verdict": r["analysis"]["verdict"],
            "disposition": r["analysis"].get("disposition"),
            "findings": [x.get("code") for x in r["analysis"].get("reasons", [])],
            "summary": (r["analysis"].get("summary") or "")[:240],
            "agent_rank": r["analysis"].get("rank_score", 0),
            "measured_expense": r.get("measured_expense", 0),
            "runs_per_day": r["runs_per_day"],
            "facts": r.get("flags", []),
        }
        for r in judged[:12]
    ]
    dash = result.get("dashboards") or {}
    facts = json.dumps(
        {
            "summary": result["summary"],
            "portfolio": result.get("portfolio", {}),
            "duplicates": {
                k: v for k, v in (result.get("duplicates") or {}).items() if k != "clusters"
            },
            "vendor_defaults": (result.get("vendor_defaults") or {}).get("count", 0),
            "datamodels_flagged": (result.get("datamodels") or {}).get("flagged", 0),
            "dashboards": {
                k: v for k, v in dash.items() if k != "items"
            },
            "top_judged_searches": top,
        }
    )
    return [
        {
            "role": "system",
            "content": (
                "You are SPL Critic's scheduler health analyst. You receive measured "
                "facts (JSON) about a Splunk environment's scheduled searches and "
                "dashboards: your own per-search verdicts and dispositions, a "
                "minute-slot herd analysis vs scheduler capacity, utilization, skip "
                "reasons, dispatch lag, scan budget, duplicate clusters, and "
                "dashboard refresh load. Write a terse executive read (4-6 "
                "sentences, plain prose, cite the numbers; punctuate with periods, "
                "commas, or colons, never em or en dashes) and up to 5 prioritized "
                "recommendations. Attribute each to what owns it: the query, the "
                "schedule, the workload, or the platform. Recommend only what the "
                "facts support; say what is still pending analysis. Respond with a "
                "single JSON object matching the provided schema."
            ),
        },
        {"role": "user", "content": facts},
    ]


class AuditHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line: str = "", command_arg: str = "") -> None:  # noqa: ARG002
        super().__init__()
        self._bundle: dict | None = None
        self._fragments: dict | None = None
        self._client_factory = splunkd_client.from_request  # test seam
        self._driver_factory = OpenRouterDriver

    def _get_bundle(self) -> dict:
        if self._bundle is None:
            self._bundle = knowledge.load_bundle()
        return self._bundle

    def _get_fragments(self) -> dict:
        if self._fragments is None:
            self._fragments = knowledge.load_fragments()
        return self._fragments

    def _model_tier(self, client) -> tuple[dict | None, str | None]:
        """(llm settings, api key) when the model tier is configured, else
        (None, None). Building the driver itself is deferred: a cached-only
        pass needs the key material for cache keys but never calls a model."""
        try:
            settings = app_config.llm_settings(client)
            api_key = credentials.get_api_key(client)
            if settings["enabled"] and settings["models"] and api_key:
                return settings, api_key
        except Exception:
            pass
        return None, None

    def handle(self, in_string: str) -> dict[str, Any]:
        try:
            request = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            request = {}

        args: dict[str, Any] = {}
        for key, value in request.get("query", []) or []:
            args[key] = value
        if request.get("payload"):
            try:
                body = json.loads(request["payload"])
                if isinstance(body, dict):
                    args.update(body)
            except json.JSONDecodeError:
                pass

        client = self._client_factory(request)
        if client is None:
            return {"status": 401, "payload": {"error": "no splunkd session"}}

        # Stored-run read paths — browsing history must never trigger a live
        # audit, so both short-circuit before any bundle or audit work.
        if str(args.get("list_runs", "")).lower() in ("1", "true", "yes"):
            try:
                limit = max(1, int(args.get("limit", _RUN_LIST_LIMIT)))
            except (TypeError, ValueError):
                limit = _RUN_LIST_LIMIT
            return {"status": 200, "payload": {"runs": audit_store.recent_runs(client, limit)}}
        get_run = args.get("get_run")
        if isinstance(get_run, str) and get_run.strip():
            stored = audit_store.get_run(client, get_run.strip())
            if stored is None:
                return {"status": 404, "payload": {"error": "no stored run with that id"}}
            stored["saved_run"] = True
            return {"status": 200, "payload": stored}

        bundle = self._get_bundle()
        try:
            custom, _errors = custom_rules.fetch(client)
            bundle = custom_rules.effective_bundle(
                bundle, custom, app_config.extra_guidance(client)
            )
        except Exception:
            pass  # audit proceeds on the compiled bundle alone
        audit.set_bands(bundle)

        names = args.get("names") if isinstance(args.get("names"), list) else None
        result = audit.run_audit(client, names=names)
        result["ruleset_version"] = bundle.get("ruleset_version", "")
        user = (request.get("session", {}) or {}).get("user", "unknown")

        with contextlib.suppress(Exception):  # dashboards: invocation-owned load
            result["dashboards"] = dashboards.scan(client)

        settings, api_key = self._model_tier(client)
        result["llm_available"] = settings is not None
        want_llm = bool(args.get("llm"))
        wanted_dash = args.get("dashboards") if isinstance(args.get("dashboards"), list) else []

        if settings is not None:
            rv = f"{bundle.get('ruleset_version', '')}/p{prompts.PROMPT_VERSION}"
            driver = None
            if want_llm:
                driver = self._driver_factory(
                    api_key,
                    settings["models"],
                    timeout=settings["timeout"],
                    reasoning=settings["reasoning"],
                )
            try:
                budget = float(args.get("time_budget", _ENRICH_TIME_BUDGET_S))
            except (TypeError, ValueError):
                budget = _ENRICH_TIME_BUDGET_S
            started = time.time()
            state = {"enriched": 0, "remaining": 0}

            def judge(spl: str, context: dict, extra: list | None, source: str,
                      search_name: str = "", app: str = "", chosen: bool = True) -> dict | None:
                """Cached analysis, else a fresh one when a driver and budget
                allow; None when the row stays pending."""
                key = guards.cache_key(spl, rv, settings["models"], context)
                rec = inference_store.get_cached(client, key)
                cached = inference_store.result_from_record(rec) if rec else None
                if cached is not None and cached.get("status") == "analyzed":
                    cached["cached"] = True
                    return cached
                if driver is None or not chosen:
                    return None
                if time.time() - started > budget:
                    state["remaining"] += 1
                    return None
                full = critic.critique_with_llm(
                    spl, bundle, self._get_fragments(), driver,
                    context=context, extra_codes=extra,
                )
                if full.get("status") == "analyzed":
                    state["enriched"] += 1
                    with contextlib.suppress(Exception):
                        inference_store.store(
                            client,
                            inference_store.build_record(
                                key, spl, full, user=user, source=source,
                                search_name=search_name, app=app,
                            ),
                        )
                return full

            # which rows the agent should judge fresh this pass
            if names:
                chosen_names = set(names)
            elif want_llm:
                try:
                    top = int(args.get("top", _LLM_ENRICH_CAP))
                except (TypeError, ValueError):
                    top = _LLM_ENRICH_CAP
                chosen_names = {r["name"] for r in result["results"][: max(top, 0)]}
            else:
                chosen_names = set()

            try:
                for row in result["results"]:
                    full = judge(
                        row["spl"], _row_context(row), audit.indicator_codes(row),
                        "audit", row["name"], row["app"], row["name"] in chosen_names,
                    )
                    if full is not None:
                        row["analysis"] = analysis_block(full, row.get("runs_per_day", 0))
            except Exception as e:
                result["llm_enrich_error"] = str(e)

            # dashboards: the agent judges each inline panel search with its
            # refresh cadence as context; a dashboard's verdict is its worst panel
            try:
                for item in (result.get("dashboards") or {}).get("items", []):
                    judged = []
                    for search in item.get("searches", []):
                        if not search.get("spl") or search.get("base"):
                            continue
                        full = judge(
                            search["spl"], _dashboard_context(item, search), None,
                            "dashboard", item.get("name", ""), item.get("app", ""),
                            item.get("name") in wanted_dash,
                        )
                        if full is None:
                            continue
                        judged.append(
                            {
                                "id": search.get("id", ""),
                                "verdict": full.get("verdict"),
                                "risk_score": full.get("risk_score", 0),
                                "cost_score": full.get("cost_score", 0),
                                "summary": full.get("summary", ""),
                                "suggested_spl": full.get("suggested_spl"),
                                "reasons": full.get("reasons", []),
                                "model": full.get("model"),
                                "cached": bool(full.get("cached")),
                                "llm_error": full.get("llm_error"),
                            }
                        )
                    if judged:
                        worst = max(
                            judged, key=lambda j: _VERDICT_RANK.get(str(j.get("verdict")), 0)
                        )
                        item["analysis"] = {
                            "verdict": worst.get("verdict"),
                            "summary": worst.get("summary", ""),
                            "model": worst.get("model"),
                            "searches": judged,
                        }
            except Exception as e:
                result["llm_enrich_error"] = str(e)

            result["llm_enriched"] = state["enriched"]
            result["llm_remaining"] = state["remaining"]

        audit.finalize(result)

        if args.get("health_read") and settings is not None:
            try:
                driver = self._driver_factory(
                    api_key, settings["models"], timeout=settings["timeout"],
                    reasoning=settings["reasoning"],
                )
                response = driver.complete_json(_health_messages(result), _HEALTH_SCHEMA)
                result["health_read"] = response.content | {"model": response.model}
            except Exception as e:
                result["health_read"] = {"error": str(e)}

        result["user"] = user

        # persistence: only full audits are recorded, and only when explicitly
        # asked (record defaults true; the UI passes record=false on its
        # auto-load so page visits don't pollute the history). A run_id passed
        # back by the client upserts the SAME run — the portfolio analysis
        # loop re-runs the audit each pass, and continuity keeps one session
        # one browsable run, stored in its final judged state.
        record = str(args.get("record", True)).lower() not in ("false", "0", "")
        if names is None:
            rid = args.get("run_id")
            rid = rid.strip() if isinstance(rid, str) else ""
            if rid and not _RUN_ID_RE.match(rid):
                rid = ""
            with contextlib.suppress(Exception):
                # prior runs — a continuation pass excludes its own run so the
                # trend line never counts the in-flight session twice
                result["run_history"] = [
                    r for r in audit_store.recent_runs(client)
                    if not (rid and r.get("run_id") == rid)
                ]
            if record:
                with contextlib.suppress(Exception):
                    env = environment.summary(client)  # what this ran against
                    if env:
                        result["environment"] = env
                with contextlib.suppress(Exception):
                    result["run_id"] = audit_store.store_run(client, result, user, run_id=rid)

        return {"status": 200, "payload": result}
