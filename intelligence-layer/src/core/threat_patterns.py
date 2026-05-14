"""Threat patterns — flow-keyed taxonomy of east-west attack signatures.

Replaces SID-keyed lookups for pure-log mode. Each pattern describes a flow
signature the agent matches against incoming `eve.json type:flow` events,
plus recommended severity/action/MITRE mapping.

Coverage spans the lab's current scenarios and the Yatesbury benchmark from
the NetVigil paper (NSDI'24).

Source of truth: knowledge/infra/threat-patterns.md
"""
from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel


class ThreatPattern(BaseModel):
    """One flow-signature → severity/action mapping entry."""

    id: str
    threat_class: str                       # policy_violation / behavioral_anomaly / reconnaissance / ...
    flow_signature: dict[str, Any]          # condition fields the agent matches
    description: str
    severity: Optional[str] = None          # P1 / P2 / P3 / P4 — fixed
    severity_inference: Optional[list[str]] = None        # rules for variable severity
    severity_progression: Optional[list[Any]] = None      # multi-stage progression
    mitre_tactic: str
    mitre_technique: Optional[str] = None
    recommended_action: Any                 # str OR list (multi-stage)
    recommended_scope: Optional[str] = None
    recommended_ttl_seconds: Any = 0        # int OR str
    confidence_baseline: Any = 0.0                     # float OR str-with-comment
    requires_corroboration: Optional[Any] = None       # list[str] OR single str
    false_positive_scenarios: Optional[list[str]] = None
    ref_yatesbury: Optional[str] = None
    ref_lab_scenario: Optional[str] = None
    note: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Pattern catalog — populated from knowledge/infra/threat-patterns.md at import.
#
# Authoring source: knowledge/infra/threat-patterns.md
# Bootstrap path:   .md → knowledge_parser → these vars (at import time)
# Runtime path:     replaced in-place at app startup by Neo4j read (future).
# ─────────────────────────────────────────────────────────────────────────────
from . import knowledge_parser as _kp

_pattern_data = _kp.parse_threat_patterns()
ALL_PATTERNS: list[ThreatPattern] = list(_pattern_data["patterns"])
PATTERNS_BY_ID: dict[str, ThreatPattern] = {p.id: p for p in ALL_PATTERNS}
PATTERNS_BY_CLASS: dict[str, list[ThreatPattern]] = {}
for p in ALL_PATTERNS:
    PATTERNS_BY_CLASS.setdefault(p.threat_class, []).append(p)

DIFFICULTY_TIERS: dict[str, Any] = _pattern_data.get("detection_difficulty_tiers", {})
PAPER_INSIGHTS: list[dict[str, Any]] = _pattern_data.get("insights", [])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def get_pattern(pattern_id: str) -> Optional[ThreatPattern]:
    return PATTERNS_BY_ID.get(pattern_id)


def patterns_for_zone_pair(src_zone: str, dst_zone: str) -> list[ThreatPattern]:
    """Return patterns whose flow_signature mentions either zone."""
    out: list[ThreatPattern] = []
    for p in ALL_PATTERNS:
        sig = p.flow_signature
        sig_str = str(sig).lower()
        if (src_zone.lower() in sig_str or dst_zone.lower() in sig_str
                or "any" in sig_str or "workload" in sig_str):
            out.append(p)
    return out


def patterns_for_dst_port(dst_port: int) -> list[ThreatPattern]:
    """Return patterns whose flow_signature targets this port."""
    out: list[ThreatPattern] = []
    for p in ALL_PATTERNS:
        sig = p.flow_signature
        port_val = sig.get("dst_port")
        if port_val is None:
            continue
        if isinstance(port_val, list) and dst_port in port_val:
            out.append(p)
        elif port_val == dst_port or port_val == "any":
            out.append(p)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Renderers
# ─────────────────────────────────────────────────────────────────────────────
def _render_pattern(p: ThreatPattern) -> str:
    sev = p.severity or "(variable, see inference)"
    action = p.recommended_action if isinstance(p.recommended_action, str) else "(multi-stage)"
    ttl = p.recommended_ttl_seconds
    parts = [
        f"- **{p.id}** [{p.threat_class}, {sev}]",
        f"  - Signature: {p.flow_signature}",
        f"  - MITRE: {p.mitre_tactic}" + (f" / {p.mitre_technique}" if p.mitre_technique else ""),
        f"  - Action: {action}  · TTL: {ttl}s  · Confidence anchor: {p.confidence_baseline}",
    ]
    if p.requires_corroboration:
        parts.append(f"  - Requires corroboration: {', '.join(p.requires_corroboration)}")
    if p.false_positive_scenarios:
        parts.append(f"  - FP scenarios: {'; '.join(p.false_positive_scenarios)}")
    if p.ref_yatesbury:
        parts.append(f"  - Yatesbury ref: {p.ref_yatesbury}")
    if p.note:
        parts.append(f"  - Note: {p.note}")
    return "\n".join(parts)


def render_for_prompt() -> str:
    """FULL render — all patterns grouped by class. Used for startup / debugging."""
    parts: list[str] = [
        "## THREAT PATTERNS — Flow-keyed taxonomy "
        f"({len(ALL_PATTERNS)} patterns across {len(PATTERNS_BY_CLASS)} classes)\n",
        "Match incoming `eve.json type:flow` events against these signatures to "
        "identify the threat class, severity, and recommended action.\n",
    ]
    for cls, patterns in sorted(PATTERNS_BY_CLASS.items()):
        parts.append(f"\n### Class: {cls} ({len(patterns)} patterns)\n")
        for p in patterns:
            parts.append(_render_pattern(p))

    if DIFFICULTY_TIERS:
        parts.append("\n### Detection Difficulty Tiers (NetVigil NSDI'24 anchor)\n")
        for tier_name, tier in DIFFICULTY_TIERS.items():
            parts.append(f"- **{tier_name}**: AUC {tier.get('netvigil_auc')}, "
                         f"agent confidence anchor {tier.get('agent_confidence_anchor')}")
            if tier.get("patterns"):
                parts.append(f"  - Patterns: {', '.join(tier['patterns'])}")
            if tier.get("reasoning_aid"):
                parts.append(f"  - Reasoning aid: {tier['reasoning_aid']}")

    return "\n".join(parts)


def render_for_alert(src_zone: str = "", dst_zone: str = "",
                     dst_port: int = 0) -> str:
    """Alert-scoped render — only patterns relevant to the observed flow."""
    candidates = patterns_for_zone_pair(src_zone, dst_zone) if src_zone or dst_zone else list(ALL_PATTERNS)
    if dst_port:
        port_specific = patterns_for_dst_port(dst_port)
        candidates = list({p.id: p for p in (candidates + port_specific)}.values())

    parts: list[str] = [
        f"## THREAT PATTERNS (alert-scoped, {len(candidates)} candidates)\n",
        "These flow patterns are most relevant to the current observation. "
        "Match the flow against `flow_signature` and adopt the recommended severity/action.\n",
    ]
    for p in candidates:
        parts.append(_render_pattern(p))

    parts.append(
        "\n### Procedure\n"
        "1. Match the incoming flow event 5-tuple + rate against each `flow_signature`.\n"
        "2. Pick the FIRST matching pattern (top-down by class importance).\n"
        "3. Adopt that pattern's severity/action as starting point.\n"
        "4. Apply `severity-scoring.md` rubric for any signal adjustment.\n"
        "5. Verify `requires_corroboration` items via past_incidents before P1 DROP."
    )
    return "\n".join(parts)
