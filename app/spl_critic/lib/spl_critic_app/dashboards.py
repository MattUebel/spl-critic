"""Dashboard inventory — the searches a dashboard dispatches, and how often.

An open dashboard re-dispatches its searches on its refresh cadence, so a
panel refreshing every 30s over a 24h window is a scheduled search nobody
scheduled — and nobody sees it in the saved-search list. This reads dashboard
DEFINITIONS from /data/ui/views (Simple XML and Dashboard Studio JSON) and
extracts, per search, the SPL, time window, refresh interval and chaining, so
dashboard refresh can be treated as an invocation-owned scan source next to
saved searches and data-model acceleration.

Facts only: no verdicts, no rule matching. Chained (post-process) searches
are recorded but do not count as dispatches — they consume their base's
results. Viewer count is unknown, so est_searches_per_hour is per open copy
of the dashboard.

Runs on Splunk's bundled Python 3.9.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from spl_critic_app.splunkd_client import SplunkdClient

# NB no output_mode here — the splunkd client appends it; a duplicate is a 400.
_VIEWS = "/servicesNS/-/-/data/ui/views"
_PAGE_SIZE = 100

# "30", "30s", "5m", "2h", "1d" — bare numbers are seconds
_REFRESH_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_REFRESH_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}

# Studio data-source types that dispatch or reference a search
_STUDIO_TYPES = ("ds.search", "ds.chain", "ds.savedSearch")


def refresh_seconds(value: Any) -> int | None:
    """Refresh cadence in seconds; None when absent, unparseable or zero."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        secs = int(value)
        return secs if secs > 0 else None
    m = _REFRESH_RE.match(str(value))
    if not m:
        return None
    secs = int(m.group(1)) * _REFRESH_UNITS[m.group(2).lower()]
    return secs if secs > 0 else None


def list_views(client: SplunkdClient) -> list:
    """All dashboard/view entries in the environment, paged; [] on failure."""
    entries: list = []
    offset = 0
    try:
        while True:
            status, doc = client.get_json(f"{_VIEWS}?count={_PAGE_SIZE}&offset={offset}")
            if status != 200:
                break
            page = (doc or {}).get("entry", []) or []
            entries.extend(page)
            offset += len(page)
            total = (doc.get("paging", {}) or {}).get("total", 0)
            if not page or offset >= total:
                break
    except Exception:
        return []
    return entries


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def _search_fact(
    sid: str,
    spl: str,
    earliest: str,
    latest: str,
    refresh_raw: Any,
    refresh_type: Any,
    base: Any,
    ref: Any,
) -> dict:
    refresh_s = refresh_seconds(refresh_raw)
    return {
        "id": sid,
        "spl": spl,
        "earliest": earliest,
        "latest": latest,
        "refresh_s": refresh_s,
        "refresh_type": (str(refresh_type) if refresh_type else "delay") if refresh_s else "",
        "base": str(base) if base else None,
        "ref": str(ref) if ref else None,
        "realtime": earliest.startswith("rt") or latest.startswith("rt"),
    }


def _simplexml_searches(root: ET.Element) -> list:
    """Every <search> in a Simple XML dashboard/form, in document order."""
    page_refresh = root.get("refresh")  # legacy whole-page refresh, seconds
    parents = {child: parent for parent in root.iter() for child in parent}
    panel_pos = {panel: i + 1 for i, panel in enumerate(root.iter("panel"))}
    per_panel: dict = {}
    searches = []
    for el in root.iter("search"):
        panel = parents.get(el)
        while panel is not None and panel.tag != "panel":
            panel = parents.get(panel)
        n = panel_pos.get(panel, 0)  # 0 = outside any panel (global base search)
        per_panel[n] = per_panel.get(n, 0) + 1
        own_refresh = el.get("refresh")
        searches.append(_search_fact(
            sid=el.get("id") or f"panel{n}.search{per_panel[n]}",
            spl=_text(el.find("query")),
            earliest=_text(el.find("earliest")),
            latest=_text(el.find("latest")) or "now",
            # a search's own refresh attribute (even "0") wins over the page's
            refresh_raw=page_refresh if own_refresh is None else own_refresh,
            refresh_type=el.get("refreshType") or el.get("refresh_type"),
            base=el.get("base"),
            ref=el.get("ref"),
        ))
    return searches


def _studio_searches(root: ET.Element) -> list | None:
    """Every dispatching data source in a Studio definition; None if unreadable."""
    definition = json.loads(_text(root.find("definition")))
    if not isinstance(definition, dict):
        return None
    defaults = (definition.get("defaults") or {}).get("dataSources") or {}
    searches = []
    for ds_id, ds in (definition.get("dataSources") or {}).items():
        if not isinstance(ds, dict) or ds.get("type") not in _STUDIO_TYPES:
            continue
        kind = ds["type"]
        opts = ds.get("options") or {}
        fallback = (defaults.get(kind) or {}).get("options") or {}
        params = opts.get("queryParameters") or {}
        fallback_params = fallback.get("queryParameters") or {}
        searches.append(_search_fact(
            sid=str(ds_id),
            spl=str(opts.get("query") or "").strip(),
            earliest=str(params.get("earliest", fallback_params.get("earliest", "")) or ""),
            latest=str(params.get("latest", fallback_params.get("latest", "now")) or "now"),
            refresh_raw=opts.get("refresh", fallback.get("refresh")),
            refresh_type=opts.get("refreshType", fallback.get("refreshType")),
            base=opts.get("extend") if kind == "ds.chain" else None,
            ref=opts.get("ref") if kind == "ds.savedSearch" else None,
        ))
    return searches


def _parse(entry: dict) -> dict | None:
    content = entry.get("content", {}) or {}
    xml_text = content.get("eai:data") or ""
    if not str(xml_text).strip():
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    # isDashboard is advisory; the root tag is authoritative (<view> etc. skip)
    if root.tag not in ("dashboard", "form"):
        return None

    studio = root.get("version") == "2"
    searches = _studio_searches(root) if studio else _simplexml_searches(root)
    if not searches:
        return None

    # chains post-process their base's results: not a dispatch of their own
    dispatching = [s for s in searches if s["refresh_s"] and not s["base"]]
    acl = entry.get("acl", {}) or {}
    return {
        "name": entry.get("name", ""),
        "app": acl.get("app", ""),
        "owner": acl.get("owner", ""),
        "label": _text(root.find("label")) or entry.get("name", ""),
        "kind": "studio" if studio else "simplexml",
        "searches": searches,
        "refreshing_searches": len(dispatching),
        "realtime_searches": sum(1 for s in searches if s["realtime"]),
        "min_refresh_s": min((s["refresh_s"] for s in dispatching), default=None),
        "est_searches_per_hour": int(round(sum(3600 / s["refresh_s"] for s in dispatching))),
    }


def parse_dashboard(entry: dict) -> dict | None:
    """DashboardFacts for one /data/ui/views entry.

    None when the entry is not a dashboard/form, has no searches, or is
    malformed (bad XML, bad Studio JSON). Never raises.
    """
    try:
        return _parse(entry)
    except Exception:
        return None


def scan(client: SplunkdClient) -> dict[str, Any]:
    """Inventory every dashboard; items ranked by estimated dispatches/hour."""
    items = []
    for entry in list_views(client):
        facts = parse_dashboard(entry)
        if facts is not None:
            items.append(facts)
    return {
        "count": len(items),
        "refreshing_searches": sum(d["refreshing_searches"] for d in items),
        "realtime_searches": sum(d["realtime_searches"] for d in items),
        "est_searches_per_hour": sum(d["est_searches_per_hour"] for d in items),
        "items": sorted(items, key=lambda d: -d["est_searches_per_hour"]),
    }
