"""Production traffic baselines — behavioral fingerprint of the datacenter.

Anything matching these patterns is normal operation. Anything outside this set is
either (a) new application behavior or (b) intrusion. Agent uses this to baseline.

Production language only — these are real traffic flows of a running datacenter, not
test fixtures.

Source of truth: knowledge/01-DATAPLANE.md §5
"""
from enum import Enum
from pydantic import BaseModel


class FlowCriticality(str, Enum):
    CRITICAL = "critical"     # Disrupting this breaks user-facing function
    HIGH = "high"             # Disrupting degrades cascade-dependent services
    MEDIUM = "medium"         # Disrupting degrades governance/visibility
    LOW = "low"


class TrafficPattern(BaseModel):
    name: str
    src_zone: str
    src_ip: str
    dst_zone: str
    dst_ip: str
    dst_port: int
    proto: str
    cadence: str                          # human description, e.g. "every 30s"
    expected_volume_per_hour: int
    burst_anomaly_threshold: str          # what makes this pattern look anomalous
    production_description: str          # 2-3 sentences, production language
    criticality_to_business: FlowCriticality
    if_disrupted: str


# ─────────────────────────────────────────────────────────────────────────────
# Baseline catalogs — populated from knowledge/infra/baselines.md at import.
#
# Authoring source: knowledge/infra/baselines.md
# Bootstrap path:   .md → knowledge_parser → these vars (at import time)
# Runtime path:     replaced in-place at app startup by Neo4j read.
# ─────────────────────────────────────────────────────────────────────────────
from . import knowledge_parser as _kp

_baseline_data = _kp.parse_baselines()
ALL_BASELINES: list[TrafficPattern] = list(_baseline_data["patterns"])
APPLICATION_FLOWS: list[TrafficPattern] = [p for p in ALL_BASELINES if p.src_zone != "MGT"]
MANAGEMENT_FLOWS: list[TrafficPattern] = [p for p in ALL_BASELINES if p.src_zone == "MGT"]
ANOMALOUS_PATTERNS: list[str] = list(_baseline_data["anomalous_patterns"])
STEADY_STATE_FLOWS_PER_MINUTE: int = _baseline_data["steady_state_flows_per_minute"]
MGT_AUDIT_ALERT_RATE_PER_MINUTE: int = _baseline_data["mgt_audit_alert_rate_per_minute"]

# Legacy literal definitions removed. Edit knowledge/infra/baselines.md instead.


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def match_baseline(src_ip: str, dst_ip: str, dst_port: int, proto: str = "tcp") -> TrafficPattern | None:
    """Return baseline pattern that this flow tuple matches, or None."""
    bare_src = src_ip.split("/")[0]
    bare_dst = dst_ip.split("/")[0]
    for p in ALL_BASELINES:
        if p.proto != proto:
            continue
        if p.dst_port != dst_port:
            continue
        if p.src_ip != bare_src:
            continue
        if p.dst_ip in ("rotating", bare_dst):
            return p
    return None


def _render_pattern_full(p: TrafficPattern) -> str:
    return (
        f"- **{p.name}**: {p.src_ip} → {p.dst_ip}:{p.dst_port}/{p.proto}, {p.cadence}, "
        f"~{p.expected_volume_per_hour}/hr, criticality={p.criticality_to_business.value}\n"
        f"  - {p.production_description}\n"
        f"  - Anomaly trigger: {p.burst_anomaly_threshold}\n"
        f"  - If disrupted: {p.if_disrupted}"
    )


def render_for_prompt() -> str:
    """Full baseline render — startup verification."""
    parts: list[str] = ["## PRODUCTION TRAFFIC BASELINES\n"]
    parts.append(
        f"Steady-state east-west volume: ~{STEADY_STATE_FLOWS_PER_MINUTE} flows/minute. "
        f"MGT audit emissions ~{MGT_AUDIT_ALERT_RATE_PER_MINUTE}/minute (SID 9000020) are "
        "REQUIRED VISIBILITY, not incidents.\n"
    )
    parts.append("### Application traffic (business workload)\n")
    parts.extend(_render_pattern_full(p) for p in APPLICATION_FLOWS)
    parts.append("\n### Management plane traffic\n")
    parts.extend(_render_pattern_full(p) for p in MANAGEMENT_FLOWS)
    parts.append("\n### Anomalous patterns (NOT in baseline — red flags)\n")
    parts.extend(f"- {s}" for s in ANOMALOUS_PATTERNS)
    return "\n".join(parts)


def render_for_alert(src_ip: str = "", dst_ip: str = "") -> str:
    """Render ONLY baselines involving src_ip or dst_ip + always-relevant anomaly patterns.

    If neither src nor dst matches any baseline, emits a short note and full anomaly list.
    """
    bare_src = src_ip.split("/")[0] if src_ip else ""
    bare_dst = dst_ip.split("/")[0] if dst_ip else ""

    relevant: list[TrafficPattern] = []
    for p in ALL_BASELINES:
        if (bare_src and p.src_ip == bare_src) or (bare_dst and p.dst_ip in (bare_dst, "rotating")):
            relevant.append(p)

    parts: list[str] = ["## PRODUCTION TRAFFIC BASELINES (alert-specific slice)\n"]
    parts.append(
        f"Steady-state datacenter volume: ~{STEADY_STATE_FLOWS_PER_MINUTE} flows/minute. "
        f"SID 9000020 emissions ~{MGT_AUDIT_ALERT_RATE_PER_MINUTE}/minute are required visibility, not incidents.\n"
    )

    if relevant:
        parts.append("### Baselines involving the alert IPs\n")
        parts.extend(_render_pattern_full(p) for p in relevant)
    else:
        parts.append("### Baselines: this src/dst pair is NOT part of any known production flow.\n"
                     "All other east-west baselines involve other IPs and are not relevant to this decision.")

    parts.append("\n### Anomalous patterns (NOT in baseline — red flags)\n")
    parts.extend(f"- {s}" for s in ANOMALOUS_PATTERNS)
    return "\n".join(parts)
