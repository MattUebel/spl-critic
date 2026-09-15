"""The agent loop with tools — evidence-gathering critique on the OpenRouter
tools protocol. Hand-rolled, bounded, no framework.

The agent receives the same context-complete prompt as the single-shot path,
plus tools: it can run the search (and its own rewrite candidates) under
guards, pull scheduler/_audit telemetry for saved searches, validate SPL
against the parser, and read the index inventory. After at most MAX_ITERS
tool rounds it must produce the standard critique JSON — now grounded in
evidence it gathered itself. Latency is accepted by design: this is the
"how it works in the real world" tier, run ahead of time and cached.

Every tool is read-only or guarded (side-effect blocklist, | head cap,
bounded window, hard timeout) — the agent can investigate, not mutate.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
from typing import Any

from spl_critic_app import audit, critic, deep, prompts, redact
from spl_critic_app.llm_backend import LLMError
from spl_critic_app.splunkd_client import SplunkdClient

MAX_ITERS = 5
_TOOL_RESULT_CAP = 4000  # chars per tool result sent back to the model

_AGENT_DOCTRINE = (
    "You have tools. Investigate before judging: run the search under guards to "
    "measure scan/event/result counts and filtering efficiency, run your rewrite "
    "candidate to A/B it against the original under the same window, pull "
    "scheduler and audit telemetry for saved searches, validate rewrites with the "
    "parser, and check which indexes exist. Never claim a rewrite is faster until "
    "you have measured both under the same envelope; a rewrite that changes the "
    "result semantics is not an improvement. Cite measured numbers in your "
    "findings. Tool budget is small — measure what matters, then conclude."
)


def _tools_spec() -> list:
    def tool(name: str, description: str, params: dict, required: list) -> dict:
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": {
                    "type": "object",
                    "properties": params,
                    "required": required,
                },
            },
        }

    spl_param = {"spl": {"type": "string", "description": "The SPL search to run"}}
    name_param = {"name": {"type": "string", "description": "The saved search name"}}
    return [
        tool(
            "run_search_sample",
            "Execute a search under guards (| head 1000, bounded window, 30s "
            "timeout, side-effect commands refused) and return measured "
            "scanCount/eventCount/resultCount, runtime, and filtering "
            "efficiency. Use it on the original search to prove cost, and on "
            "your rewrite to prove the improvement.",
            spl_param,
            ["spl"],
        ),
        tool(
            "get_scheduler_stats",
            "30-day scheduler telemetry for a saved search from _internal: "
            "runs, skips, skip ratio, average runtime, zero-result rate.",
            name_param,
            ["name"],
        ),
        tool(
            "get_search_history",
            "30-day execution history for a saved search from _audit: events "
            "scanned/kept/returned per run and measured filtering efficiency.",
            name_param,
            ["name"],
        ),
        tool(
            "validate_spl",
            "Check whether an SPL string parses on this instance.",
            spl_param,
            ["spl"],
        ),
        tool(
            "get_index_inventory",
            "The index names defined on this instance — catches searches "
            "reading from indexes that do not exist here.",
            {},
            [],
        ),
    ]


def _execute_tool(
    client: SplunkdClient, bundle: dict, context: dict | None, name: str, args: dict
) -> dict:
    if name == "run_search_sample":
        return deep.run_guarded(client, str(args.get("spl", "")), bundle, context=context)
    if name == "get_scheduler_stats":
        stats = audit.scheduler_stats(client).get(str(args.get("name", "")))
        return stats or {"error": "no scheduler telemetry for that saved search (30d)"}
    if name == "get_search_history":
        hist = audit.history_stats(client, bundle).get(str(args.get("name", "")))
        return hist or {"error": "no _audit history for that saved search (30d)"}
    if name == "validate_spl":
        return {"valid": deep.validate_rewrite(client, str(args.get("spl", "")))}
    if name == "get_index_inventory":
        return {"indexes": sorted(audit.defined_index_names(client))}
    return {"error": f"unknown tool: {name}"}


def _same_spl(a: str, b: str) -> bool:
    return " ".join(a.split()) == " ".join(b.split())


def critique_deep(
    client: SplunkdClient,
    spl: str,
    bundle: dict,
    fragments: dict,
    driver: Any,
    context: dict | None = None,
    max_iters: int = MAX_ITERS,
    extra_codes: list | None = None,
) -> dict[str, Any]:
    """Agent-loop critique. A tools-path failure degrades to the single-shot
    judgment, which itself reports `unavailable` if the model is unreachable."""
    codes = critic.indicators(spl, bundle, context, extra_codes)
    safe_spl, redactions = redact.redact_spl(spl)
    messages = prompts.build_messages(safe_spl, codes, bundle, fragments, context)
    messages[0]["content"] += "\n\n" + _AGENT_DOCTRINE
    size = prompts.prompt_size(messages)

    trace = []
    evidence = None
    agent_cost = 0.0
    try:
        for _ in range(max_iters):
            message, usage = driver.complete_tools(messages, _tools_spec())
            agent_cost += float(usage.get("cost", 0) or 0)
            calls = message.get("tool_calls") or []
            if not calls:
                break
            messages.append(message)
            for call in calls:
                fn = call.get("function", {}) or {}
                tool_name = str(fn.get("name", ""))
                try:
                    tool_args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    tool_args = {}
                try:
                    output = _execute_tool(client, bundle, context, tool_name, tool_args)
                except Exception as e:
                    output = {"error": f"tool failed: {e}"}
                if (
                    tool_name == "run_search_sample"
                    and "error" not in output
                    and _same_spl(str(tool_args.get("spl", "")), safe_spl)
                ):
                    evidence = output  # the agent measured the original itself
                trace.append({"tool": tool_name, "args": tool_args, "result": output})
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id", ""),
                        "content": json.dumps(output)[:_TOOL_RESULT_CAP],
                    }
                )
        messages.append(
            {
                "role": "user",
                "content": (
                    "Investigation complete. Produce the final critique as a single "
                    "JSON object per the schema — ground findings and scores in the "
                    "evidence you gathered, and cite measured numbers in your reasons."
                ),
            }
        )
        response = driver.complete_json(messages, prompts.CRITIQUE_SCHEMA)
    except LLMError:
        # the tools path failed — fall back to the plain single-shot judgment
        # (which itself reports unavailable if the model is unreachable)
        result = critic.critique_with_llm(
            spl, bundle, fragments, driver, context=context, extra_codes=extra_codes
        )
        result["agent_error"] = "agent tools unavailable; single-shot judgment served"
        if trace:
            result["agent_trace"] = trace
        return result

    result = critic.judge(codes, response, bundle)
    result["tier"] = "agent+tools"
    result["agent_trace"] = trace
    result["agent_cost"] = round(agent_cost, 6)
    result["redactions"] = redactions
    result["prompt"] = size
    if evidence is not None:
        result["evidence"] = evidence
    return result
