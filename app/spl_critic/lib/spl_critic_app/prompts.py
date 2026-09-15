"""Prompt assembly for the agent — built ONLY from compiled knowledge.

The system prompt carries the doctrine and the knowledgebase brief: one
compiled fragment per coded pattern, as VOCABULARY and rationale the agent
reasons with. The user prompt carries the SPL, the search's measured context,
the static indicators (inputs for the agent's consideration, never
conclusions), and deterministic few-shot examples from the corpus. No
hand-written rule text anywhere.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

from typing import Any

# Bump on ANY prompt-affecting change (doctrine, output rules, digest, context
# block, schema). ruleset_version only tracks compiled knowledge — without
# this in the cache key, a prompt edit would keep serving critiques produced
# by the old prompt. (Caught live: the digest-2 experiment.)
# 9 = the context block states what an all-time window MEANS (every run
#     rescans the whole retention) and the indicators line no longer says
#     "not conclusions" (v8 still approved a scoped all-time search saying
#     "the dispatch window is not judged here")
# 8 = lanes attribute, never exempt: the search is judged as it runs
# 7 = agent-only doctrine: model scores stand, disposition, lanes, dashboard
#     context, indicators framed as inputs (6 = no-dash style; 5 = digest-1)
PROMPT_VERSION = "9"

# Strict structured-output schema (OpenRouter/OpenAI json_schema rules:
# every property required, additionalProperties false).
CRITIQUE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["approved", "warn", "blocked"]},
        # keep = leave it as it is; fix = rewrite or reschedule; retire =
        # disable or remove (reads from nowhere, disabled but scheduled,
        # produces nothing anyone consumes, duplicates another search)
        "disposition": {"type": "string", "enum": ["keep", "fix", "retire"]},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "cost_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "reasons": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "message": {"type": "string"},
                },
                "required": ["code", "message"],
                "additionalProperties": False,
            },
        },
        # plain string, not a null union: Anthropic's structured-output path
        # (via OpenRouter) rejects union types; empty string means "no rewrite"
        "suggested_spl": {"type": "string"},
        "summary": {"type": "string"},
    },
    "required": [
        "verdict", "disposition", "risk_score", "cost_score", "reasons",
        "suggested_spl", "summary",
    ],
    "additionalProperties": False,
}

_DOCTRINE = (
    "You are SPL Critic, the sole judge of Splunk SPL searches. Splunk search is "
    "map-reduce: indexers retrieve and filter buckets in parallel (distributable "
    "streaming commands); the search head centralizes (centralized streaming, "
    "transforming, orchestrating commands). Every event that reaches the search head "
    "unnecessarily costs network, memory, and scheduler capacity. Judge searches by "
    "structure: retrieval scoping, wildcard use, pipeline order, command placement, "
    "subsearch/truncation risk, and cheaper equivalents (stats over transaction, "
    "tstats over stats on indexed fields). Judge them by their history too: the "
    "schedule, the dispatch window, and the measured telemetry supplied as context "
    "are facts about how the search really runs, and you judge the search AS IT RUNS: "
    "an unbounded dispatch window, a hyperactive schedule, or a hot dashboard refresh "
    "is a finding against this search even when the SPL text itself is well-formed. "
    "Attribute each finding to what owns it: the query (structure), the invocation "
    "(schedule, window, dashboard refresh cadence), the workload (concurrency, "
    "skips), or the platform. Attribution says who fixes it, never whether it "
    "counts. A heavy search alone does not prove platform pressure, and a heavy "
    "search is not necessarily a broken one. The knowledgebase brief below is your "
    "vocabulary and rationale; static indicators handed to you are inputs to weigh, "
    "never conclusions."
)

_OUTPUT_RULES = (
    # 'JSON' must appear literally: some providers downgrade json_schema to
    # json_object mode and reject requests whose messages never say 'json'.
    "Output rules: respond with a single JSON object matching the provided schema. "
    "reasons[].code MUST come from the vocabulary above — never invent "
    "codes. Explain each reason in terms of pipeline structure and data flow, "
    "citing measured numbers from the context when they support it. "
    "Ground every finding in the SPL text or the provided search context — "
    "never guess about context you were not given (e.g. report ALLTIME_RANGE "
    "only when the SPL or the provided dispatch window shows an unbounded "
    "range; with no window in evidence, stay silent on window findings). "
    "Static indicators are inputs, not orders: confirm the ones the SPL and "
    "context support, and omit any the context shows to be harmless. "
    "risk_score and cost_score are integers on a 0 to 100 scale: 0 is nothing "
    "to worry about, 100 is the worst search this platform could run; keep "
    "them consistent with the severity of the findings you confirm. "
    "disposition is 'keep' when the search should stay as it is, 'fix' when it "
    "should be rewritten or rescheduled, and 'retire' when it should be "
    "disabled or removed (it reads from nowhere, is disabled yet scheduled, "
    "produces nothing anyone consumes, or duplicates another search). Ad-hoc "
    "SPL with no schedule is 'keep' or 'fix'. "
    "suggested_spl must be a single complete rewritten search preserving the "
    "original intent; use the empty string when the search is already "
    "well-formed. If the search is clean, verdict is 'approved' with an empty "
    "reasons list — do not manufacture findings. Style: plain prose in "
    "summary and messages; punctuate with periods, commas, or colons, and "
    "never use em or en dashes."
)


def _vocabulary(bundle: dict, fragments: dict) -> str:
    lines = []
    frag_texts = fragments.get("fragments", {})
    for rule in bundle["rules"]:
        if rule.get("kind") == "evidence":
            continue  # runtime-metric codes; the agent never emits them
        # custom rules carry their fragment inline (built at fetch time)
        lines.append("- " + frag_texts.get(rule["id"], rule.get("fragment", rule["id"])))
    return "\n".join(lines)


def _limits_digest(bundle: dict) -> str:
    parts = []
    for name, rec in sorted(bundle.get("limits", {}).get("limits", {}).items()):
        parts.append(f"{name}={rec['value']} {rec['unit']} ({rec['failure_mode']})")
    return "; ".join(parts)


def _verdict_policy_digest(bundle: dict) -> str:
    """The severity→verdict policy, stated so the agent's verdict is calibrated
    to the same contract the knowledgebase encodes."""
    policy = bundle.get("verdict_policy", {})
    block_at = policy.get("block_at")
    warn_at = policy.get("warn_at")
    return (
        "Verdict policy (calibrate your verdict and scores to it): a finding at "
        f"severity '{block_at}' or above → verdict 'blocked'; at '{warn_at}' or "
        "above → 'warn'; otherwise 'approved'. risk_score and cost_score should "
        "track the worst finding, consistent with the rule weights in the "
        "vocabulary. A finding you dismiss as harmless in context must not "
        "count toward the verdict."
    )
    # This digest is EXACTLY the measured-best variant (2.8% clean-SPL FP,
    # build/eval/results-fullauth-digest1.json). Two "improvements" measured
    # worse and were reverted: a stricter justify-deviations rule (FP 8.3%,
    # digest2) and numeric score-scale calibration — per-rule weights (FP
    # 16.7%) and a severity ladder (FP 11.1%) both made the model over-flag
    # borderline-clean rewrites. Changes must re-run `spl-critic eval`
    # before shipping.


_ALLTIME_MARKERS = ("0", "@0", "0.000", "alltime", "all-time")


def _context_block(context: dict | None) -> str:
    """Render the search's dispatch context as authoritative facts.

    Context starvation was the top measured hallucination driver (models
    guessing ALLTIME_RANGE with no window in sight — docs/model-eval.md), so
    the window, schedule, and measured telemetry are stated explicitly, and
    their absence is stated explicitly too.
    """
    if not context:
        return (
            "Search context: none provided — this SPL is being reviewed as text "
            "only. The dispatch window is unknown; judge only what the SPL shows."
        )
    lines = []
    earliest = str(context.get("earliest", "") or "").strip()
    latest = str(context.get("latest", "") or "").strip() or "now"
    if "earliest" in context:
        if earliest.lower() in _ALLTIME_MARKERS or earliest == "":
            lines.append(
                "- Dispatch window: ALL TIME (earliest is unbounded), latest=" + latest + ". "
                "This window is part of how the search runs: every execution rescans the "
                "index's entire retention, and the cost grows with the data forever. That is "
                "the ALLTIME_RANGE finding unless the SPL bounds time itself or it is a "
                "generating command that reads no index."
            )
        else:
            lines.append(f"- Dispatch window: earliest={earliest} latest={latest}")
        lines.append("- Time modifiers written inside the SPL override this dispatch window.")
    if context.get("kind") == "dashboard":
        refresh = context.get("refresh_s")
        cadence = (
            f"refreshes every {refresh:g}s ({context.get('refresh_type') or 'delay'}) "
            "while the dashboard is open"
            if refresh
            else "runs each time the dashboard is opened, no auto-refresh"
        )
        lines.append(
            f"- Dashboard panel search in '{context.get('name', '?')}': {cadence}. "
            "Viewer count is unknown, so every open browser tab is another dispatcher; "
            "the refresh cadence is invocation-owned cost, separate from the query."
        )
    elif context.get("name"):
        lines.append(f"- Saved search: {context['name']}")
    if context.get("cron"):
        runs = context.get("runs_per_day")
        freq = f" (~{runs:g} runs/day)" if runs else ""
        lines.append(f"- Scheduled: cron '{context['cron']}'{freq}")
    telemetry = context.get("telemetry") or {}
    if telemetry:
        rendered = ", ".join(
            f"{key}={value}" for key, value in sorted(telemetry.items()) if value is not None
        )
        lines.append("- Measured telemetry (last 30 days, from this instance's logs): " + rendered)
    audit_facts = context.get("facts") or {}
    if audit_facts:
        rendered = ", ".join(
            f"{key}={value}" for key, value in sorted(audit_facts.items()) if value is not None
        )
        lines.append("- Gathered facts about this search: " + rendered)
    if not lines:
        return (
            "Search context: none provided — this SPL is being reviewed as text "
            "only. The dispatch window is unknown; judge only what the SPL shows."
        )
    return (
        "Search context (authoritative facts about how this search runs — ground "
        "window, schedule, and cost findings in these):\n" + "\n".join(lines)
    )


def _select_few_shot(fragments: dict, tier1_codes: list, count: int = 2) -> list:
    """Deterministic few-shot pick: prefer examples sharing indicator codes."""
    shots = fragments.get("few_shot", [])
    relevant = [s for s in shots if set(s.get("codes", [])) & set(tier1_codes)]
    chosen = relevant[:count]
    for shot in shots:
        if len(chosen) >= count:
            break
        if shot not in chosen:
            chosen.append(shot)
    return chosen


def prompt_size(messages: list) -> dict:
    """Rough size of an assembled prompt, for context-budget instrumentation.

    The rule vocabulary is stuffed into every prompt (no per-request retrieval
    yet), so prompt size grows with the catalog. Logging it per critique makes
    that growth visible — the trigger for switching to code-keyed selective
    injection is a measured threshold, not a guess (see docs/ROADMAP.md,
    "Knowledge retrieval scaling"). Token estimate uses the ~4-chars/token
    heuristic; no tokenizer dependency on Splunk's bundled Python.
    """
    chars = sum(len(m.get("content", "")) for m in messages)
    system = next((len(m["content"]) for m in messages if m.get("role") == "system"), 0)
    return {"chars": chars, "est_tokens": (chars + 3) // 4, "system_chars": system}


def build_messages(
    spl: str,
    tier1_codes: list,
    bundle: dict,
    fragments: dict,
    context: dict | None = None,
) -> list:
    sections = [
        _DOCTRINE,
        "Knowledgebase brief — the coded pattern vocabulary (the ONLY valid "
        "reasons[].code values), each with its rationale:\n"
        + _vocabulary(bundle, fragments),
        "Platform limits you may cite: " + _limits_digest(bundle),
        _verdict_policy_digest(bundle),
        _OUTPUT_RULES,
    ]
    if bundle.get("extra_guidance"):
        sections.append(
            "Environment-specific guidance from the local Splunk admin (treat as "
            "authoritative context about THIS deployment):\n" + bundle["extra_guidance"]
        )
    system = "\n\n".join(sections)

    if tier1_codes:
        tier1_text = (
            "Static indicators (pattern matches on the SPL text and its dispatch "
            "context, inputs for your judgment): " + ", ".join(tier1_codes)
            + ". Confirm each one the SPL and context support; dismiss one only when "
            "the context shows it is harmless here, and say why in the summary."
        )
    else:
        tier1_text = "Static indicators: none matched."

    examples = []
    for shot in _select_few_shot(fragments, tier1_codes):
        examples.append(
            f"BAD: {shot['bad_spl']}\n"
            f"CODES: {', '.join(shot['codes'])}\n"
            f"REWRITE: {shot['good_spl']}"
        )
    examples_text = ("Worked examples:\n" + "\n---\n".join(examples)) if examples else ""

    user = "\n\n".join(
        filter(
            None,
            [
                "Critique this SPL search.",
                _context_block(context),
                tier1_text
                + " Weigh these against the SPL and the context, then look for "
                "pipeline-relational issues static matching cannot see (command "
                "ordering, data flow, map-reduce placement, truncation risk), "
                "and produce the best rewrite.",
                examples_text,
                "SPL:\n" + spl,
            ],
        )
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
