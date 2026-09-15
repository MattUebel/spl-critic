"""The critique pipeline: gather indicators → the agent judges → one result.

The agent is the only verdict authority. The deterministic pass here produces
INDICATORS (coded pattern matches on the SPL text and its dispatch context)
that go into the agent's prompt as inputs; they are never presented to a user
as findings. When no model can be reached the result is honestly
`unavailable`: no verdict, no scores, no findings — a rulebook does not get
to judge.

Standard result shape (endpoint, UI, Auditor):
  {status, verdict, disposition, risk_score, cost_score, reasons[],
   suggested_spl, summary, tier, inputs{...}, ruleset_version, ...}

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import re
from typing import Any

from spl_critic_app import detectors, knowledge, prompts, redact, spl_parser
from spl_critic_app.llm_backend import LLMError, LLMResponse

# explicit all-time markers; "" covers savedsearches.conf's unset default,
# which callers normalize to "0" before building context (unset in an ad-hoc
# request means "unknown", and unknown must never flag)
_ALLTIME_EARLIEST = ("", "0", "@0", "0.000", "alltime", "all-time")


# inline time modifiers override the dispatch window in Splunk — an SPL that
# sets its own earliest= is not governed by the saved search's window (and the
# inline-alltime case is already the regex detector's job)
_INLINE_EARLIEST = re.compile(r"(?i)\bearliest\s*=")

VERDICTS = ("approved", "warn", "blocked")
DISPOSITIONS = ("keep", "fix", "retire")


def context_codes(context: dict | None, bundle: dict, spl: str = "") -> list:
    """Deterministic indicators visible only with dispatch context.

    The window is not in the SPL text, so text-only analysis can never flag it
    (and the model used to hallucinate it — docs/model-eval.md). With the
    window supplied by the caller, an unbounded range is a fact, not a guess.
    """
    if not context or "earliest" not in context:
        return []
    if _INLINE_EARLIEST.search(spl or ""):
        return []
    codes = []
    earliest = str(context.get("earliest", "") or "").strip().lower()
    if earliest in _ALLTIME_EARLIEST and "ALLTIME_RANGE" in knowledge.rule_index(bundle):
        codes.append("ALLTIME_RANGE")
    return codes


def indicators(
    spl: str, bundle: dict, context: dict | None = None, extra_codes: list | None = None
) -> list:
    """The static indicator codes for a search: detectors over the parsed
    pipeline, context codes from the dispatch window, plus any caller-supplied
    schedule/telemetry codes (the audit tier's config+history checks).
    Sorted, de-duplicated. INPUT to the agent, never a finding."""
    pipeline = spl_parser.parse(spl)
    codes = set(detectors.run_detectors(pipeline, bundle))
    codes.update(context_codes(context, bundle, spl))
    index = knowledge.rule_index(bundle)
    for code in extra_codes or []:
        if code in index:
            codes.add(index[code]["id"])
    return sorted(codes)


def critique(
    spl: str, bundle: dict | None = None, context: dict | None = None
) -> dict[str, Any]:
    """INTERNAL: the deterministic measuring stick.

    Policy-over-indicators, used by the eval harness and the corpus
    regression tests to check the knowledgebase itself. It is NOT a
    user-facing verdict and no endpoint returns it as one.
    """
    bundle = bundle or knowledge.load_bundle()
    codes = indicators(spl, bundle, context)
    result = knowledge.verdict_for_codes(codes, bundle)
    index = knowledge.rule_index(bundle)
    for reason in result["reasons"]:
        rule = index[reason["code"]]
        reason["detail"] = " ".join(str(rule["cost_rationale"]).split())
        reason["doc"] = rule["doc_citation"]
    result.update(
        {
            "codes": codes,
            "tier": "indicators",
            "ruleset_version": bundle.get("ruleset_version", ""),
        }
    )
    return result


def unavailable(
    codes: list, bundle: dict, reason: str, error: str | None = None
) -> dict[str, Any]:
    """The honest no-judgment result: the agent could not run, so nothing is
    judged. Indicators ride along under `inputs` for diagnostics only."""
    result: dict[str, Any] = {
        "status": "unavailable",
        "unavailable_reason": reason,
        "verdict": None,
        "disposition": None,
        "risk_score": 0,
        "cost_score": 0,
        "reasons": [],
        "suggested_spl": None,
        "summary": "",
        "tier": "none",
        "inputs": {
            "indicators": list(codes),
            "confirmed": [],
            "dismissed": [],
            "added": [],
            "dropped": [],
        },
        "ruleset_version": bundle.get("ruleset_version", ""),
    }
    if error:
        result["llm_error"] = error
    if reason == "rate_limited":
        result["rate_limited"] = True
    return result


def _scores(content: dict, verdict: str) -> tuple[int, int]:
    """The agent's own 0-100 scores, with a scale guard.

    Models were caught live answering on a 0-10 scale; with a non-approved
    verdict and both scores in single digits, that is what happened, so the
    pair is scaled up rather than rendered as near-empty meters.
    """

    def _int(value: Any) -> int:
        try:
            return int(round(float(value)))
        except (TypeError, ValueError):
            return 0

    risk, cost = _int(content.get("risk_score")), _int(content.get("cost_score"))
    if verdict != "approved" and 0 < max(risk, cost) <= 10:
        risk, cost = risk * 10, cost * 10
    return max(0, min(100, risk)), max(0, min(100, cost))


def judge(codes: list, llm: LLMResponse, bundle: dict) -> dict[str, Any]:
    """Turn the agent's structured reply into the standard result.

    The verdict, disposition, scores, and findings are the agent's. Its
    reason codes are validated against the knowledgebase vocabulary (aliases
    canonicalized, unknown codes dropped) so every finding links back to a
    rationale and a doc citation. What the agent did with the static
    indicators is recorded under `inputs` for evaluation, not for display.
    """
    index = knowledge.rule_index(bundle)

    messages = {}  # canonical code -> message, in the agent's order
    dropped = []
    for reason in llm.content.get("reasons", []) or []:
        code = str(reason.get("code", "")).strip().upper()
        if code in index:
            messages.setdefault(index[code]["id"], str(reason.get("message", "") or ""))
        elif code:
            dropped.append(code)

    confirmed = list(messages)
    verdict = str(llm.content.get("verdict", "")).lower()
    if verdict not in VERDICTS:
        if not confirmed:
            # nothing usable came back: that is not a judgment, say so
            return unavailable(codes, bundle, "llm_error", "model returned a malformed verdict")
        # malformed verdict but real findings: derive the verdict from them,
        # using the policy the prompt asked the agent to calibrate to
        verdict = knowledge.verdict_for_codes(confirmed, bundle)["verdict"]
    disposition = str(llm.content.get("disposition", "")).lower()
    if disposition not in DISPOSITIONS:
        disposition = "keep" if verdict == "approved" else "fix"
    risk, cost = _scores(llm.content, verdict)

    return {
        "status": "analyzed",
        "verdict": verdict,
        "disposition": disposition,
        "risk_score": risk,
        "cost_score": cost,
        "reasons": [
            {
                "code": c,
                "message": messages[c] or index[c]["name"],
                "severity": index[c]["severity"],
                "detail": " ".join(str(index[c]["cost_rationale"]).split()),
                "doc": index[c]["doc_citation"],
            }
            for c in confirmed
        ],
        "suggested_spl": llm.content.get("suggested_spl") or None,
        "summary": str(llm.content.get("summary", "") or ""),
        "tier": "agent",
        "inputs": {
            "indicators": list(codes),
            "confirmed": [c for c in confirmed if c in codes],
            "dismissed": [c for c in codes if c not in confirmed],
            "added": [c for c in confirmed if c not in codes],
            "dropped": sorted(set(dropped)),
        },
        "ruleset_version": bundle.get("ruleset_version", ""),
        "model": llm.model,
        "usage": llm.usage,
        "latency_ms": llm.latency_ms,
    }


def critique_with_llm(
    spl: str,
    bundle: dict,
    fragments: dict,
    driver: Any,
    redact_keys=redact.DEFAULT_DENY_KEYS,
    context: dict | None = None,
    extra_codes: list | None = None,
) -> dict[str, Any]:
    """The agent's single-shot judgment. Model unreachable → `unavailable`.

    Indicators are computed on the real SPL; the agent only ever sees a
    redacted copy, since the model path is the only place SPL text leaves
    the instance. `context` (dispatch window, schedule, measured telemetry,
    gathered facts) is the evidence the agent judges with; `extra_codes` are
    schedule/telemetry indicators the audit tier computed for this search.
    """
    codes = indicators(spl, bundle, context, extra_codes)
    safe_spl, redactions = redact.redact_spl(spl, redact_keys)
    messages = prompts.build_messages(safe_spl, codes, bundle, fragments, context)
    size = prompts.prompt_size(messages)  # context-budget instrumentation
    try:
        response = driver.complete_json(messages, prompts.CRITIQUE_SCHEMA)
    except LLMError as e:
        result = unavailable(codes, bundle, "llm_error", str(e))
    else:
        result = judge(codes, response, bundle)
    result["redactions"] = redactions
    result["prompt"] = size
    return result
