"""Tokenize SPL into pipeline stages for structural analysis.

Not a grammar — a pragmatic splitter: stages are split on top-level pipes
(quotes and subsearch brackets respected), each stage gets a command name,
and the implicit first `search` stage is modeled explicitly so detectors
can reason about retrieval separately from the rest of the pipeline.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_COMMENT_RE = re.compile(r"```.*?```", re.DOTALL)
_COMMAND_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")


@dataclass
class Stage:
    text: str  # raw stage text, stripped
    command: str  # lowercased command ('search' for the implicit first stage)
    args: str  # stage text minus the command token


@dataclass
class Pipeline:
    text: str  # cleaned full SPL (comments stripped)
    generating: bool = False  # True when the SPL starts with `| <command>`
    stages: list = field(default_factory=list)

    @property
    def retrieval(self) -> Stage | None:
        """The (possibly implicit) search stage that reads from indexes."""
        if self.stages and not self.generating:
            return self.stages[0]
        return None

    def commands(self) -> list:
        return [s.command for s in self.stages]


def strip_comments(spl: str) -> str:
    return _COMMENT_RE.sub(" ", spl)


def split_stages(spl: str) -> list:
    """Split on pipes that are outside quotes and subsearch brackets."""
    parts = []
    buf = []
    depth = 0
    quote = None  # the active quote char, or None
    for ch in spl:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == "[":
            depth += 1
            buf.append(ch)
        elif ch == "]":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "|" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts]


def parse(spl: str) -> Pipeline:
    text = strip_comments(spl).strip()
    starts_generating = text.startswith("|")
    pipeline = Pipeline(text=text, generating=starts_generating)

    segments = split_stages(text)
    if starts_generating and segments and segments[0] == "":
        segments = segments[1:]

    first = True
    for segment in segments:
        if not segment:
            continue
        if first and not starts_generating:
            # retrieval stage: implicit (`index=web error`) or explicit
            # (`search index=web error`) — either way, command is 'search'
            args = re.sub(r"(?i)^search\b\s*", "", segment)
            pipeline.stages.append(Stage(text=segment, command="search", args=args))
            first = False
            continue
        first = False
        m = _COMMAND_RE.match(segment)
        command = m.group(1).lower() if m else ""
        args = segment[m.end() :].strip() if m else segment
        pipeline.stages.append(Stage(text=segment, command=command, args=args))
    return pipeline


# --- field-level helpers used by the pipeline-relational detectors ---------

_FILTER_FIELD_RE = re.compile(r"([A-Za-z_][\w.]*)\s*(?:!=|<=|>=|=|<|>)")
_EVAL_TARGET_RE = re.compile(r"(?:^|,)\s*([A-Za-z_][\w]*)\s*=")
_REX_GROUP_RE = re.compile(r"\(\?<([A-Za-z_][\w]*)>")
_AS_ALIAS_RE = re.compile(r"\bAS\s+([A-Za-z_][\w]*)", re.IGNORECASE)
_LOOKUP_OUTPUT_RE = re.compile(r"\bOUTPUT(?:NEW)?\b(.*)$", re.IGNORECASE | re.DOTALL)

# Commands whose output fields we can enumerate. Anything not listed here is
# treated as an unknown producer, which suppresses movability conclusions.
_TRANSPARENT = {"search", "where", "head", "tail", "sort", "dedup", "fields", "table", "regex"}


def filter_fields(stage: Stage) -> set:
    """Field names referenced by comparison predicates in a filter stage."""
    return set(_FILTER_FIELD_RE.findall(stage.args))


def produced_fields(stage: Stage):
    """(fields, known): fields a stage introduces; known=False → can't tell."""
    cmd, args = stage.command, stage.args
    if cmd in _TRANSPARENT:
        return set(), True
    if cmd == "eval":
        return set(_EVAL_TARGET_RE.findall(args)), True
    if cmd == "rex":
        return set(_REX_GROUP_RE.findall(args)), True
    if cmd == "lookup":
        m = _LOOKUP_OUTPUT_RE.search(args)
        if not m:
            return set(), False  # bare lookup outputs every lookup column
        out = m.group(1)
        fields = set(_AS_ALIAS_RE.findall(out))
        fields |= {
            tok for tok in re.findall(r"[A-Za-z_][\w]*", out) if tok.upper() not in ("AS",)
        }
        return fields, True
    return set(), False
