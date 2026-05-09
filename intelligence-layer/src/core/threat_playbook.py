"""Threat playbook — adversary kill chains plausible against this datacenter.

This is the agent's mental model of HOW attackers compromise the system. Each kill chain
maps Suricata SIDs to MITRE ATT&CK stages with production-language semantics. Agent uses
this to correlate single alerts into multi-stage campaigns.

Production language only — adversary scenarios are realistic threats, not test cases.

Source of truth: knowledge/01-DATAPLANE.md §7.2, §8
"""
from pydantic import BaseModel


class SidDetection(BaseModel):
    """A single Suricata signature in operational use."""
    sid: int
    severity_p_level: int             # 1=critical, 2=high, 3=info-recon, 4=audit
    signature_msg: str
    production_description: str
    mitre_tactic: str
    mitre_technique: str
    detection_logic: str              # match criteria, threshold
    uses_flags_s_workaround: bool     # asymmetric capture caveat
    recommended_response: str         # "DROP src_ip" | "log_only" | "escalate"
    default_ttl_seconds: int          # 0 = log_only
    false_positive_likelihood: str    # "low" | "medium" | "high"
    false_positive_scenarios: list[str]


class KillChainStage(BaseModel):
    stage: int
    tactic: str
    expected_signals: list[int]       # SIDs
    production_indicators: str
    false_positive_sources: list[str]


class KillChain(BaseModel):
    name: str
    production_description: str
    stages: list[KillChainStage]
    typical_dwell_between_stages: str
    recommended_intervention_point: str   # which stage to block first
    containment_strategy: str


# ─────────────────────────────────────────────────────────────────────────────
# SID + KillChain catalogs — populated from knowledge/infra/*.md at import.
#
# Authoring source: knowledge/infra/{sids,kill-chains}.md
# Bootstrap path:   .md → knowledge_parser → these vars (at import time)
# Runtime path:     replaced in-place at app startup by Neo4j read.
# ─────────────────────────────────────────────────────────────────────────────
from . import knowledge_parser as _kp

SID_DETECTIONS: dict[int, SidDetection] = _kp.parse_sids()
KILL_CHAINS: list[KillChain] = _kp.parse_kill_chains()

# Legacy literal definitions removed. Edit knowledge/infra/{sids,kill-chains}.md instead.

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def get_sid_detection(sid: int) -> SidDetection | None:
    return SID_DETECTIONS.get(sid)


def find_kill_chain_stage(sid: int) -> list[tuple[KillChain, KillChainStage]]:
    """Return all kill chain stages where this SID could fire."""
    matches: list[tuple[KillChain, KillChainStage]] = []
    for kc in KILL_CHAINS:
        for stage in kc.stages:
            if sid in stage.expected_signals:
                matches.append((kc, stage))
    return matches


def _render_sid_detail(d: SidDetection) -> str:
    return (
        f"- **SID {d.sid}** (P{d.severity_p_level}, {d.mitre_tactic} / {d.mitre_technique})\n"
        f"  - Signature: {d.signature_msg}\n"
        f"  - {d.production_description}\n"
        f"  - Detection: {d.detection_logic}\n"
        f"  - Recommended: {d.recommended_response} (TTL {d.default_ttl_seconds}s)\n"
        f"  - False positive likelihood: {d.false_positive_likelihood}\n"
        f"  - FP scenarios: {'; '.join(d.false_positive_scenarios) or '(none)'}"
    )


def _render_kill_chain(kc: KillChain) -> str:
    parts = [
        f"\n**{kc.name}**",
        f"- Threat: {kc.production_description}",
        f"- Dwell between stages: {kc.typical_dwell_between_stages}",
        f"- Intervention point: {kc.recommended_intervention_point}",
        f"- Containment: {kc.containment_strategy}",
        "- Stages:",
    ]
    for stage in kc.stages:
        sids_str = ", ".join(f"SID {s}" for s in stage.expected_signals)
        parts.append(f"  - Stage {stage.stage} ({stage.tactic}) — signals: {sids_str}. {stage.production_indicators}")
    return "\n".join(parts)


def render_for_prompt() -> str:
    """FULL render — used for startup verification."""
    parts: list[str] = ["## THREAT PLAYBOOK — Active Suricata Detections & Kill Chains\n"]
    parts.append("### Active SID Inventory (8 detections)\n")
    parts.extend(_render_sid_detail(d) for d in SID_DETECTIONS.values())
    parts.append("\n### Kill Chains (multi-stage adversary playbooks)\n")
    parts.extend(_render_kill_chain(kc) for kc in KILL_CHAINS)
    return "\n".join(parts)


def render_for_alert(sid: int) -> str:
    """Render ONLY this SID's detail (no kill-chain leakage).

    Kill chains are intentionally NOT injected into the agent's prompt: doing so
    would hand the agent the test-scenario answer (e.g., "SID 9000001 = stage 2
    of presentation-tier-breach playbook → block") and turn reasoning into
    pattern-matching. Kill-chain knowledge remains in Neo4j and is reachable via
    the `query_kg` tool when the agent decides it needs to reason about
    multi-stage campaigns. The agent must INFER lateral movement / exfiltration
    from primitives (zone violation, baseline absence, MITRE technique), not
    from a pre-baked playbook.
    """
    parts: list[str] = ["## THREAT PLAYBOOK (alert-specific slice)\n"]

    # Full detail for this SID
    target = SID_DETECTIONS.get(sid)
    parts.append("### Triggered detection\n")
    if target:
        parts.append(_render_sid_detail(target))
    else:
        parts.append(f"- SID {sid}: UNKNOWN — not in active inventory. Treat with caution.")

    # Short reference of other SIDs (for context awareness)
    other_sids = [d for s, d in SID_DETECTIONS.items() if s != sid]
    if other_sids:
        parts.append("\n### Other SIDs in active inventory (reference only)\n")
        for d in other_sids:
            parts.append(
                f"- SID {d.sid} (P{d.severity_p_level}): {d.signature_msg} — {d.recommended_response}"
            )

    parts.append(
        "\n### Multi-stage campaign analysis\n"
        "Kill-chain playbooks are NOT pre-loaded here. If you suspect this alert is\n"
        "part of a multi-stage attack, use `query_kg` to traverse `(Sid)-[:EXPECTED_IN]->(KillChain)`\n"
        "and decide based on what you find. Otherwise reason from primitives:\n"
        "baseline violation, MITRE technique, blast radius, asset criticality."
    )

    return "\n".join(parts)
