"""Near-duplicate saved-search detection — the "you cloned this 14 times" signal.

Dashboards and alerts get copy-pasted — one per team, per index, per threshold —
and each copy becomes a separate scheduled search nobody remembers is a twin.
This groups saved searches by a normalized SPL *signature* (structure with
numeric and string literals masked), so searches that differ only in a constant
land in the same cluster. Pure static analysis over the SPL text: no telemetry,
no execution, deterministic — O(n) via a signature dict, not pairwise.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import re
from typing import Any

from spl_critic_app import spl_parser

_WS = re.compile(r"\s+")
_PIPE = re.compile(r"\s*\|\s*")
_DQ = re.compile(r'"[^"]*"')
_SQ = re.compile(r"'[^']*'")
_NUM = re.compile(r"-?\d+(?:\.\d+)?")

# Ignore clusters whose shared shape is trivially short — a bare `| metadata …`
# one-liner shared across apps is not the tech-debt story and only adds noise.
_MIN_SIGNATURE_LEN = 25


def normalize_spl(spl: str) -> str:
    """Lowercased, comment-stripped, whitespace/pipe-collapsed SPL."""
    text = spl_parser.strip_comments(spl or "").lower()
    text = _PIPE.sub(" | ", text)
    return _WS.sub(" ", text).strip()


def signature(spl: str) -> str:
    """Structural fingerprint: normalized SPL with string and numeric literals
    masked, so `status=500` and `status=502` (and `-30d` vs `-7d`) collapse to
    the same shape. Identical signature = same search modulo constants."""
    text = normalize_spl(spl)
    text = _DQ.sub('"S"', text)
    text = _SQ.sub("'S'", text)
    text = _NUM.sub("N", text)
    return text


def find_clusters(rows: list) -> dict[str, Any]:
    """Group rows (each needs spl/name/app/runs_per_day) by SPL signature.

    Returns clusters of size >= 2, ranked by member count then combined
    schedule frequency (the cost of maintaining N copies on N schedules).
    """
    groups: dict[str, list] = {}
    for row in rows:
        spl = row.get("spl", "")
        sig = signature(spl)
        if len(sig) < _MIN_SIGNATURE_LEN:
            continue
        groups.setdefault(sig, []).append(row)

    clusters = []
    for sig, members in groups.items():
        if len(members) < 2:
            continue
        distinct_spl = {normalize_spl(m.get("spl", "")) for m in members}
        clusters.append(
            {
                "signature": sig if len(sig) <= 200 else sig[:197] + "…",
                "count": len(members),
                "identical": len(distinct_spl) == 1,  # byte-identical vs const-varied
                "members": [
                    {
                        "name": m.get("name", ""),
                        "app": m.get("app", ""),
                        "runs_per_day": m.get("runs_per_day", 0),
                    }
                    for m in sorted(members, key=lambda r: -r.get("runs_per_day", 0))
                ],
                "apps": sorted({m.get("app", "") for m in members}),
                "total_runs_per_day": round(sum(m.get("runs_per_day", 0) for m in members), 1),
            }
        )

    clusters.sort(key=lambda c: (-c["count"], -c["total_runs_per_day"]))
    return {
        "clusters": clusters,
        "clusters_count": len(clusters),
        "clustered_searches": sum(c["count"] for c in clusters),
    }
