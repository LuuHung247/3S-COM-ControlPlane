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
# Active Suricata SID inventory (8 rules, verified 2026-05-04)
# ─────────────────────────────────────────────────────────────────────────────
SID_DETECTIONS: dict[int, SidDetection] = {
    9000001: SidDetection(
        sid=9000001,
        severity_p_level=1,
        signature_msg="WEB direct to DB - microsegmentation bypass",
        production_description=(
            "Detection trigger: direct connection initiated from presentation tier toward data "
            "tier database service ports. This violates defense-in-depth principle requiring "
            "application-mediated data access. Likely lateral movement preparing SQL exfiltration."
        ),
        mitre_tactic="TA0008 Lateral Movement",
        mitre_technique="T1021 Remote Services",
        detection_logic="TCP SYN from 10.1.100.0/24 to 10.1.200.0/24 dst_port in {5432,3306,1433,27017}",
        uses_flags_s_workaround=True,
        recommended_response="DROP src_ip",
        default_ttl_seconds=3600,
        false_positive_likelihood="low",
        false_positive_scenarios=[
            "Legitimate DB migration script run from WEB tier (rare, pre-announced)",
            "Misconfigured monitoring tool scraping DB from wrong zone",
        ],
    ),
    9000002: SidDetection(
        sid=9000002,
        severity_p_level=1,
        signature_msg="DB initiating outbound connection - exfiltration",
        production_description=(
            "Detection trigger: data tier initiating outbound connection beyond all internal "
            "trust zones. Violates crown-jewel invariant (DB never initiates outbound). Strong "
            "indicator of data exfiltration over C2 channel or covert tunnel."
        ),
        mitre_tactic="TA0010 Exfiltration",
        mitre_technique="T1041 Exfiltration Over C2 Channel",
        detection_logic="TCP SYN from 10.1.200.0/24 to !{WEB,DB,APP,MGT}",
        uses_flags_s_workaround=True,
        recommended_response="DROP src_ip",
        default_ttl_seconds=3600,
        false_positive_likelihood="low",
        false_positive_scenarios=[
            "OS package update from DB host (should be staged via MGT proxy, but possible)",
            "DNS resolver call (legitimate but should not happen in this datacenter)",
        ],
    ),
    9000003: SidDetection(
        sid=9000003,
        severity_p_level=2,
        signature_msg="APP reverse call to WEB - lateral movement",
        production_description=(
            "Detection trigger: application tier initiating connection toward presentation "
            "tier — direction reversal from intended dataflow. APP should never call WEB. "
            "Indicator of APP tier compromise pivoting toward web frontend."
        ),
        mitre_tactic="TA0008 Lateral Movement",
        mitre_technique="T1021 Remote Services",
        detection_logic="TCP SYN from 10.2.100.0/24 to 10.1.100.0/24 dst_port in {80,443,22}",
        uses_flags_s_workaround=True,
        recommended_response="DROP src_ip",
        default_ttl_seconds=1800,
        false_positive_likelihood="low",
        false_positive_scenarios=[],
    ),
    9000004: SidDetection(
        sid=9000004,
        severity_p_level=2,
        signature_msg="WEB to MGT - unauthorized escalation attempt",
        production_description=(
            "Detection trigger: presentation tier initiating connection toward management plane "
            "on operational ports (SSH/RDP). Lateral movement from untrusted zone into "
            "privileged management zone. Strong indicator of WEB compromise attempting "
            "credential pivot or remote shell."
        ),
        mitre_tactic="TA0008 Lateral Movement",
        mitre_technique="T1021 Remote Services",
        detection_logic="TCP SYN from 10.1.100.0/24 to 10.2.50.0/24 dst_port in {22,3389}",
        uses_flags_s_workaround=True,
        recommended_response="DROP src_ip",
        default_ttl_seconds=1800,
        false_positive_likelihood="low",
        false_positive_scenarios=[],
    ),
    9000005: SidDetection(
        sid=9000005,
        severity_p_level=2,
        signature_msg="APP to MGT - unauthorized escalation attempt",
        production_description=(
            "Detection trigger: application tier initiating connection toward management plane "
            "on operational ports. Same threat model as 9000004 but from APP tier — indicates "
            "deeper compromise reaching application layer."
        ),
        mitre_tactic="TA0008 Lateral Movement",
        mitre_technique="T1021 Remote Services",
        detection_logic="TCP SYN from 10.2.100.0/24 to 10.2.50.0/24 dst_port in {22,3389}",
        uses_flags_s_workaround=True,
        recommended_response="DROP src_ip",
        default_ttl_seconds=1800,
        false_positive_likelihood="low",
        false_positive_scenarios=[],
    ),
    9000010: SidDetection(
        sid=9000010,
        severity_p_level=3,
        signature_msg="ICMP ping sweep - reconnaissance",
        production_description=(
            "Detection trigger: ICMP echo activity from a single source exceeding 3 within 10 "
            "seconds. Indicative of network reconnaissance scanning live hosts."
        ),
        mitre_tactic="TA0043 Reconnaissance",
        mitre_technique="T1018 Remote System Discovery",
        detection_logic="ICMP echo, threshold 3 within 10s per src",
        uses_flags_s_workaround=False,
        recommended_response="log_only",
        default_ttl_seconds=0,
        false_positive_likelihood="medium",
        false_positive_scenarios=[
            "Legitimate operations team running connectivity verification",
            "Health check tools doing host enumeration",
        ],
    ),
    9000011: SidDetection(
        sid=9000011,
        severity_p_level=3,
        signature_msg="TCP port scan - reconnaissance",
        production_description=(
            "Detection trigger: TCP SYN burst from single source — 10 SYN within 5 seconds. "
            "Indicative of port-scanning behavior mapping service surface area."
        ),
        mitre_tactic="TA0043 Reconnaissance",
        mitre_technique="T1046 Network Service Discovery",
        detection_logic="TCP SYN, threshold 10 within 5s per src",
        uses_flags_s_workaround=False,
        recommended_response="log_only",
        default_ttl_seconds=0,
        false_positive_likelihood="medium",
        false_positive_scenarios=[
            "Vulnerability scanner from MGT zone",
            "Application connection-pool warmup",
        ],
    ),
    9000020: SidDetection(
        sid=9000020,
        severity_p_level=4,
        signature_msg="MGT zone access - audit baseline",
        production_description=(
            "Detection trigger: management plane initiating any flow, rate-limited to 1/min/src. "
            "BY DESIGN — required visibility for compliance. NOT an incident. Confirms management "
            "plane is operating normally."
        ),
        mitre_tactic="TA0007 Discovery",
        mitre_technique="T1082 System Information Discovery",
        detection_logic="MGT (10.2.50.0/24) → any, rate-limit 1/min/src",
        uses_flags_s_workaround=False,
        recommended_response="log_only",
        default_ttl_seconds=0,
        false_positive_likelihood="high",
        false_positive_scenarios=[
            "Every legitimate MGT scrape, audit, logpull triggers this — by design.",
        ],
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Kill chains — multi-stage adversary playbooks
# ─────────────────────────────────────────────────────────────────────────────
KILL_CHAINS: list[KillChain] = [
    KillChain(
        name="presentation-tier-breach-to-data-exfiltration",
        production_description=(
            "Adversary gains foothold on presentation tier (web-01) through external-facing "
            "service vulnerability. Conducts internal reconnaissance to map data tier. Attempts "
            "direct lateral movement bypassing application access controls. Once on data tier, "
            "exfiltrates database content over outbound channel."
        ),
        stages=[
            KillChainStage(
                stage=1, tactic="Discovery",
                expected_signals=[9000010, 9000011],
                production_indicators="Anomalous probing from compromised presentation tier toward internal services",
                false_positive_sources=["Legitimate scanner from MGT zone"],
            ),
            KillChainStage(
                stage=2, tactic="Lateral Movement",
                expected_signals=[9000001],
                production_indicators="WEB tier directly contacting DB tier on database ports — bypasses application mediation",
                false_positive_sources=[],
            ),
            KillChainStage(
                stage=3, tactic="Exfiltration",
                expected_signals=[9000002],
                production_indicators="Data tier initiating outbound connection — likely C2 callback or exfil tunnel",
                false_positive_sources=[],
            ),
        ],
        typical_dwell_between_stages="5-30 minutes",
        recommended_intervention_point="Stage 1 (block recon source IP early prevents escalation to stages 2-3)",
        containment_strategy=(
            "Block presentation tier src_ip at LEAF-1 immediately on stage 1+ detection. "
            "If stage 2+ confirmed, additionally block any DB outbound. Escalate to SOC if "
            "stage 3 reached — implies data has likely been touched."
        ),
    ),
    KillChain(
        name="application-tier-breach-pivoting",
        production_description=(
            "Adversary gains foothold on application tier (app-01), abuses legitimate APP→DB "
            "path while pivoting toward presentation tier (reverse direction) or escalating "
            "to management plane via SSH."
        ),
        stages=[
            KillChainStage(
                stage=1, tactic="Lateral Movement (reverse)",
                expected_signals=[9000003],
                production_indicators="APP tier reaching back to WEB tier — direction reversal indicates compromise",
                false_positive_sources=[],
            ),
            KillChainStage(
                stage=2, tactic="Privilege Escalation Attempt",
                expected_signals=[9000005],
                production_indicators="APP tier attempting SSH to management plane",
                false_positive_sources=[],
            ),
        ],
        typical_dwell_between_stages="2-15 minutes",
        recommended_intervention_point="Stage 1 (any APP-originated reverse flow)",
        containment_strategy=(
            "Block app-01 outbound at LEAF-2 on first reverse-direction or MGT-direction signal. "
            "Application tier compromise affects business logic integrity — high-priority response."
        ),
    ),
    KillChain(
        name="management-plane-credential-compromise",
        production_description=(
            "Adversary acquires management plane credentials (insider threat, supply chain, or "
            "credential leak). Uses MGT plane's universal access to pivot freely. Hardest "
            "scenario to detect because MGT traffic is whitelisted by design."
        ),
        stages=[
            KillChainStage(
                stage=1, tactic="Discovery (anomalous volume)",
                expected_signals=[9000020],
                production_indicators=(
                    "Spike in SID 9000020 rate beyond ~1/min baseline. Unusual destination "
                    "diversity or off-pattern timing."
                ),
                false_positive_sources=["Operations team running ad-hoc audit"],
            ),
        ],
        typical_dwell_between_stages="N/A — single-stage detection",
        recommended_intervention_point="Stage 1 (escalate to human, agent must NOT auto-block MGT)",
        containment_strategy=(
            "MGT zone is in NEVER_BLOCK list — agent CANNOT auto-block. On 9000020 anomaly "
            "(rate spike or off-pattern timing), escalate to SOC for human investigation. "
            "Auto-blocking MGT would self-DoS audit/visibility."
        ),
    ),
    KillChain(
        name="data-tier-direct-exfiltration",
        production_description=(
            "Less common but high-impact: adversary gains direct access to data tier (db-01) "
            "through database vulnerability or stolen credentials, beacons or exfiltrates data "
            "directly without going through application tier."
        ),
        stages=[
            KillChainStage(
                stage=1, tactic="Exfiltration / C2",
                expected_signals=[9000002],
                production_indicators="Any DB-originated outbound flow — DB is crown-jewel, never initiates",
                false_positive_sources=[],
            ),
        ],
        typical_dwell_between_stages="N/A — single-stage detection",
        recommended_intervention_point="Stage 1 (immediate)",
        containment_strategy=(
            "Block db-01 outbound at LEAF-1 immediately. DB outbound = data is at risk RIGHT NOW. "
            "Escalate to SOC for incident response — assume confidentiality breach."
        ),
    ),
]


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


def render_for_prompt() -> str:
    parts: list[str] = ["## THREAT PLAYBOOK — Active Suricata Detections & Kill Chains\n"]

    parts.append("### Active SID Inventory (8 detections)\n")
    for sid, d in SID_DETECTIONS.items():
        parts.append(
            f"- **SID {sid}** (P{d.severity_p_level}, {d.mitre_tactic} / {d.mitre_technique})\n"
            f"  - Signature: {d.signature_msg}\n"
            f"  - {d.production_description}\n"
            f"  - Detection: {d.detection_logic}\n"
            f"  - Recommended: {d.recommended_response} (TTL {d.default_ttl_seconds}s)\n"
            f"  - False positive likelihood: {d.false_positive_likelihood}"
        )

    parts.append("\n### Kill Chains (multi-stage adversary playbooks)\n")
    for kc in KILL_CHAINS:
        parts.append(f"\n**{kc.name}**")
        parts.append(f"- Threat: {kc.production_description}")
        parts.append(f"- Dwell between stages: {kc.typical_dwell_between_stages}")
        parts.append(f"- Intervention point: {kc.recommended_intervention_point}")
        parts.append(f"- Containment: {kc.containment_strategy}")
        parts.append("- Stages:")
        for stage in kc.stages:
            sids_str = ", ".join(f"SID {s}" for s in stage.expected_signals)
            parts.append(f"  - Stage {stage.stage} ({stage.tactic}) — signals: {sids_str}. {stage.production_indicators}")

    return "\n".join(parts)
