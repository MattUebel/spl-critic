"""Tier 1 deterministic detectors, driven by the compiled rules bundle.

Two signal kinds per rule (detection_signals):
  regexes          — {pattern, scope}: scope 'retrieval' runs against the
                     retrieval stage text, 'pipeline' against the whole SPL
  pipeline_checks  — named relational checks implemented in _CHECKS below;
                     names with no implementation are skipped (forward-compat:
                     rules can declare checks before the engine grows them)

Design constraint from the talk: regex-able issues ARE caught by regex; the
pipeline checks capture what regex cannot — relationships between commands.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import re
from typing import Any

from spl_critic_app import spl_parser
from spl_critic_app.spl_parser import Pipeline

# Fields resolvable from tsidx alone — the tstats-eligible set.
_INDEXED_FIELDS = {"index", "sourcetype", "source", "host", "splunk_server", "_time"}
_INDEXED_FILTER_RE = re.compile(
    r"^(?:index|sourcetype|source|host|splunk_server|earliest|latest)\s*=", re.IGNORECASE
)
_RETRIEVAL_NOISE = {"OR", "AND", "NOT", "(", ")"}


def _command_type(cmd: str, ctx: dict) -> str:
    return ctx.get("command_types", {}).get(cmd, {}).get("type", "")


def _filter_stage_indexes(pipeline: Pipeline) -> list:
    """Indexes of explicit `| search` filter stages (not the retrieval stage)."""
    start = 1 if pipeline.retrieval is not None else 0
    return [
        i
        for i, s in enumerate(pipeline.stages)
        if i >= max(start, 1) and s.command == "search"
    ]


def _centralized_before_filter(pipeline: Pipeline, ctx: dict) -> bool:
    filters = _filter_stage_indexes(pipeline)
    if not filters:
        return False
    return any(
        _command_type(s.command, ctx) == "centralized_streaming" and i < max(filters)
        for i, s in enumerate(pipeline.stages)
    )


def _transform_before_filter(pipeline: Pipeline, ctx: dict) -> bool:
    filters = _filter_stage_indexes(pipeline)
    if not filters:
        return False
    return any(
        _command_type(s.command, ctx) == "transforming" and i < max(filters)
        for i, s in enumerate(pipeline.stages)
    )


def _filter_after_transform_movable(pipeline: Pipeline, ctx: dict) -> bool:
    """A `| search` predicate references a field no intermediate stage created —
    it could have filtered earlier in the pipeline (or in retrieval)."""
    for i in _filter_stage_indexes(pipeline):
        if i < 2:
            continue  # directly after retrieval: the optimizer merges this
        produced = set()
        opaque = False
        for stage in pipeline.stages[1:i]:
            fields, known = spl_parser.produced_fields(stage)
            produced |= fields
            opaque = opaque or not known
        if opaque:
            continue  # something we can't model created fields; stay quiet
        if spl_parser.filter_fields(pipeline.stages[i]) - produced:
            return True
    return False


def _table_not_terminal(pipeline: Pipeline, ctx: dict) -> bool:
    return any(
        s.command == "table" and i < len(pipeline.stages) - 1
        for i, s in enumerate(pipeline.stages)
    )


def _sort_immediately_before_transaction(pipeline: Pipeline, ctx: dict) -> bool:
    cmds = pipeline.commands()
    return any(a == "sort" and b == "transaction" for a, b in zip(cmds, cmds[1:]))


def _multiple_append_stages(pipeline: Pipeline, ctx: dict) -> bool:
    return pipeline.commands().count("append") >= 2


def _multiple_rex_stages(pipeline: Pipeline, ctx: dict) -> bool:
    return pipeline.commands().count("rex") >= 3


def _dedup_without_sortby(pipeline: Pipeline, ctx: dict) -> bool:
    return any(
        s.command == "dedup" and "sortby" not in s.args.lower() for s in pipeline.stages
    )


def _join_unbounded(pipeline: Pipeline, ctx: dict) -> bool:
    for s in pipeline.stages:
        if s.command == "join" and not re.search(r"\bmax\s*=\s*[1-9]", s.args):
            return True
    return False


def _retrieval_missing_sourcetype(pipeline: Pipeline, ctx: dict) -> bool:
    r = pipeline.retrieval
    if r is None:
        return False
    text = r.text.lower()
    return "index=" in text and "sourcetype=" not in text


def _retrieval_tokens(text: str) -> list:
    """Retrieval tokens with quotes kept intact and parens peeled off."""
    tokens = re.findall(r'"[^"]*"|\S+', text)
    return [t.strip("()") for t in tokens if t.strip("()")]


def _lookup_before_aggregation(pipeline: Pipeline, ctx: dict) -> bool:
    """A `| lookup` enriches events BEFORE the first transforming command, and
    none of its OUTPUT fields feed that command's clause — so the enrichment
    could move after the aggregation and run on far fewer rows. Distinct from
    LATE_FILTER (predicate pushdown): this is enrichment-vs-transform ordering.
    Stays quiet when the lookup output is opaque (no OUTPUT clause) or a field
    it produces is actually consumed by the transform (then it must precede)."""
    xf_idx = next(
        (i for i, s in enumerate(pipeline.stages)
         if _command_type(s.command, ctx) == "transforming"),
        None,
    )
    if xf_idx is None:
        return False
    xf_args = pipeline.stages[xf_idx].args.lower()
    for stage in pipeline.stages[:xf_idx]:
        if stage.command != "lookup":
            continue
        fields, known = spl_parser.produced_fields(stage)
        if not known or not fields:
            continue  # opaque lookup (no OUTPUT) — can't reason, stay quiet
        if not any(f.lower() in xf_args for f in fields):
            return True
    return False


def _stats_on_indexed_only_fields(pipeline: Pipeline, ctx: dict) -> bool:
    """Retrieval filters only on indexed fields AND a stats stage aggregates
    only indexed fields with count/dc — the textbook tstats conversion."""
    r = pipeline.retrieval
    if r is None:
        return False
    for token in _retrieval_tokens(r.args):
        if token in _RETRIEVAL_NOISE:
            continue
        if not _INDEXED_FILTER_RE.match(token):
            return False  # raw term or non-indexed field filter → not eligible
    for s in pipeline.stages:
        if s.command != "stats":
            continue
        funcs = set(re.findall(r"([a-z_]+)\s*\(", s.args.lower()))
        if re.search(r"\bcount\b(?!\s*\()", s.args.lower()):
            funcs.add("count")
        if not funcs or not funcs <= {"count", "dc", "distinct_count"}:
            continue
        m = re.search(r"\bby\s+(.*)$", s.args, re.IGNORECASE)
        by_fields = {f.strip() for f in m.group(1).split(",")} if m else set()
        if by_fields <= _INDEXED_FIELDS:
            return True
    return False


_CHECKS = {
    "centralized_before_filter": _centralized_before_filter,
    "transform_before_filter": _transform_before_filter,
    "filter_after_transform_movable": _filter_after_transform_movable,
    "table_not_terminal": _table_not_terminal,
    "sort_immediately_before_transaction": _sort_immediately_before_transaction,
    "multiple_append_stages": _multiple_append_stages,
    "multiple_rex_stages": _multiple_rex_stages,
    "dedup_without_sortby": _dedup_without_sortby,
    "join_unbounded": _join_unbounded,
    "retrieval_missing_sourcetype": _retrieval_missing_sourcetype,
    "stats_on_indexed_only_fields": _stats_on_indexed_only_fields,
    "lookup_before_aggregation": _lookup_before_aggregation,
}


def run_detectors(pipeline: Pipeline, bundle: dict) -> list:
    """Return the sorted, de-duplicated anti-pattern codes found in the SPL."""
    ctx: dict[str, Any] = {"command_types": bundle.get("command_types", {}).get("commands", {})}
    retrieval_text = pipeline.retrieval.text if pipeline.retrieval else ""

    codes = set()
    for rule in bundle["rules"]:
        if rule.get("kind") != "detector":
            continue
        signals = rule.get("detection_signals", {})
        hit = False
        for sig in signals.get("regexes", []):
            target = retrieval_text if sig.get("scope") == "retrieval" else pipeline.text
            if target and re.search(sig["pattern"], target):
                hit = True
                break
        if not hit:
            for name in signals.get("pipeline_checks", []):
                check = _CHECKS.get(name)
                if check is not None and check(pipeline, ctx):
                    hit = True
                    break
        if hit:
            codes.add(rule["id"])
    return sorted(codes)
