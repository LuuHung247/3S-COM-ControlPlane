"""Which zone pairs each custom SID covers, derived from the SID catalogue.

The source/destination CIDRs are parsed out of each detection rule's `detection_logic`
string, so the mapping is a property of the deployed ruleset rather than a hand-written
table. Pairs with no covering SID are reported too: on those cells the IDS has no
signature, and a response system must fall back on the policy matrix alone.
"""
from __future__ import annotations

import re
from typing import Any

from . import policy, system_model
from .threat_playbook import SID_DETECTIONS
from .topology import ip_to_zone

_CIDR = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}")
_ZONE_WORD = re.compile(r"\b(WEB|APP-GW|APP-CORE|WORKER|DB-OLTP|DB-ANALYTICS|MONITORING|MON|MGT)\b")


def zones() -> list[str]:
    return sorted({z for pair in policy.POLICY_MATRIX for z in pair})


def _zones_in(text: str) -> set[str]:
    out = {ip_to_zone(c.split("/")[0].replace(".0/", ".10/").split("/")[0])
           for c in _CIDR.findall(text)}
    out |= {("MONITORING" if w == "MON" else w) for w in _ZONE_WORD.findall(text)}
    return {z for z in out if z in set(zones())}


def _split_sides(logic: str) -> tuple[str, str] | None:
    m = re.search(r"\bfrom\b(.*?)\bto\b(.*)", logic, re.S)
    return (m.group(1), m.group(2)) if m else None


def sid_zone_pairs(sid: int) -> set[tuple[str, str]]:
    """Ordered zone pairs on which this SID can fire ("" = not zone-scoped)."""
    det = SID_DETECTIONS.get(sid)
    logic = (getattr(det, "detection_logic", "") or "") if det else ""
    sides = _split_sides(logic)
    if not sides:
        return set()
    src_txt, dst_txt = sides
    all_z = set(zones())
    src = all_z - _zones_in(src_txt) if "!" in src_txt else _zones_in(src_txt)
    dst = all_z - _zones_in(dst_txt) if "!" in dst_txt else _zones_in(dst_txt)
    if "any zone" in dst_txt:
        dst = all_z
    if not src or not dst:
        return set()
    return {(s, d) for s in src for d in dst if s != d}


def coverage() -> dict[str, Any]:
    """Per-pair SID coverage across all off-diagonal zone pairs."""
    pairs = {(s, d): {"verdict": policy.POLICY_MATRIX.get((s, d), "DENY"), "sids": []}
             for s in zones() for d in zones() if s != d}
    for sid in sorted(SID_DETECTIONS):
        for pair in sid_zone_pairs(sid):
            if pair in pairs:
                pairs[pair]["sids"].append(sid)
    covered = {p for p, v in pairs.items() if v["sids"]}
    deny = {p for p, v in pairs.items() if v["verdict"] == "DENY"}
    allow = {p for p, v in pairs.items() if v["verdict"] == "ALLOW"}
    return {
        "pairs": pairs,
        "n_pairs": len(pairs),
        "n_deny": len(deny), "n_allow": len(allow),
        "deny_covered": len(deny & covered), "deny_uncovered": sorted(deny - covered),
        "allow_covered": len(allow & covered), "allow_with_sid": sorted(allow & covered),
    }


def best_sid_for(src: str, dst: str) -> int | None:
    """Most specific covering SID for a pair: fewest pairs covered, then most severe."""
    cands = [(len(sid_zone_pairs(s)), getattr(SID_DETECTIONS[s], "severity_p_level", 9), s)
             for s in SID_DETECTIONS if (src, dst) in sid_zone_pairs(s)]
    return min(cands)[2] if cands else None
