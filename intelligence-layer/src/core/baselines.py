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
# Application traffic — east-west business workload
# ─────────────────────────────────────────────────────────────────────────────
APPLICATION_FLOWS: list[TrafficPattern] = [
    TrafficPattern(
        name="web-to-application-proxy",
        src_zone="WEB", src_ip="10.1.100.10",
        dst_zone="APP", dst_ip="10.2.100.10",
        dst_port=8080, proto="tcp",
        cadence="every 30s",
        expected_volume_per_hour=120,
        burst_anomaly_threshold=">10/min sustained suggests proxy abuse or DoS",
        production_description=(
            "Presentation tier proxies user HTTP requests to the application tier for "
            "business logic processing. This is the canonical user-request east-west flow."
        ),
        criticality_to_business=FlowCriticality.CRITICAL,
        if_disrupted="End-user-facing path broken. Users cannot complete actions requiring application logic.",
    ),
    TrafficPattern(
        name="application-to-database-oltp",
        src_zone="APP", src_ip="10.2.100.10",
        dst_zone="DB", dst_ip="10.1.200.10",
        dst_port=5432, proto="tcp",
        cadence="every 30s",
        expected_volume_per_hour=120,
        burst_anomaly_threshold=">50/min sustained suggests query-loop bug or exfiltration probe",
        production_description=(
            "Application tier issues OLTP transactions against the relational database. "
            "Typical workload: SELECT users, SELECT orders, INSERT log, UPDATE session. "
            "Sustained transactional load is normal operation."
        ),
        criticality_to_business=FlowCriticality.CRITICAL,
        if_disrupted="Application cannot read/write business state. Cascade outage to user-facing operations.",
    ),
    TrafficPattern(
        name="application-database-readiness",
        src_zone="APP", src_ip="10.2.100.10",
        dst_zone="DB", dst_ip="10.1.200.10",
        dst_port=5432, proto="tcp",
        cadence="every 60s",
        expected_volume_per_hour=60,
        burst_anomaly_threshold="N/A — health check, low volume",
        production_description=(
            "Application tier performs DB connectivity readiness probe. Validates that "
            "the data tier service is accepting connections."
        ),
        criticality_to_business=FlowCriticality.MEDIUM,
        if_disrupted="Application loses early signal of DB health degradation. Outages detected later.",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Management plane traffic — audit, scrape, log retrieval (originated from MGT)
# ─────────────────────────────────────────────────────────────────────────────
MANAGEMENT_FLOWS: list[TrafficPattern] = [
    TrafficPattern(
        name="management-service-health-scrape-web",
        src_zone="MGT", src_ip="10.2.50.10",
        dst_zone="WEB", dst_ip="10.1.100.10",
        dst_port=80, proto="tcp",
        cadence="every 60s",
        expected_volume_per_hour=60,
        burst_anomaly_threshold="N/A — health check",
        production_description=(
            "Management plane probes WEB tier HTTP service health from MGT vantage. "
            "Provides operational visibility into presentation tier liveness."
        ),
        criticality_to_business=FlowCriticality.MEDIUM,
        if_disrupted="Loss of WEB tier health monitoring. Outages detected later.",
    ),
    TrafficPattern(
        name="management-service-health-scrape-app",
        src_zone="MGT", src_ip="10.2.50.10",
        dst_zone="APP", dst_ip="10.2.100.10",
        dst_port=8080, proto="tcp",
        cadence="every 60s",
        expected_volume_per_hour=60,
        burst_anomaly_threshold="N/A — health check",
        production_description=(
            "Management plane probes APP tier HTTP API health for operational monitoring."
        ),
        criticality_to_business=FlowCriticality.MEDIUM,
        if_disrupted="Loss of APP tier health monitoring.",
    ),
    TrafficPattern(
        name="management-service-health-scrape-db",
        src_zone="MGT", src_ip="10.2.50.10",
        dst_zone="DB", dst_ip="10.1.200.10",
        dst_port=5432, proto="tcp",
        cadence="every 60s",
        expected_volume_per_hour=60,
        burst_anomaly_threshold="N/A — health check",
        production_description=(
            "Management plane probes DB tier connectivity from MGT vantage. Critical for "
            "early detection of data tier service degradation."
        ),
        criticality_to_business=FlowCriticality.MEDIUM,
        if_disrupted="Loss of DB tier health monitoring.",
    ),
    TrafficPattern(
        name="management-compliance-ssh-audit",
        src_zone="MGT", src_ip="10.2.50.10",
        dst_zone="WEB+APP+DB", dst_ip="rotating",
        dst_port=22, proto="tcp",
        cadence="every 2 minutes (rotating destinations)",
        expected_volume_per_hour=30,
        burst_anomaly_threshold=">5/min on same dst suggests credential brute-force",
        production_description=(
            "Management plane performs periodic compliance SSH login across managed zones, "
            "capturing host telemetry (uptime, posture). Required by governance for audit trail."
        ),
        criticality_to_business=FlowCriticality.HIGH,
        if_disrupted="Loss of compliance audit posture. Governance violation.",
    ),
    TrafficPattern(
        name="management-application-log-retrieval",
        src_zone="MGT", src_ip="10.2.50.10",
        dst_zone="APP", dst_ip="10.2.100.10",
        dst_port=22, proto="tcp",
        cadence="every 5 minutes",
        expected_volume_per_hour=12,
        burst_anomaly_threshold="N/A — scheduled retrieval",
        production_description=(
            "Management plane retrieves application logs via SSH from APP tier for "
            "centralized log aggregation and incident analysis."
        ),
        criticality_to_business=FlowCriticality.MEDIUM,
        if_disrupted="Operational logs not centralized. Incident analysis degraded.",
    ),
]


ALL_BASELINES: list[TrafficPattern] = APPLICATION_FLOWS + MANAGEMENT_FLOWS

# Steady-state estimate
STEADY_STATE_FLOWS_PER_MINUTE = 120
MGT_AUDIT_ALERT_RATE_PER_MINUTE = 1     # SID 9000020 — by design, NOT incident


# ─────────────────────────────────────────────────────────────────────────────
# Anti-baselines — flows that MUST NOT exist (red flags)
# ─────────────────────────────────────────────────────────────────────────────
ANOMALOUS_PATTERNS: list[str] = [
    "Any flow originating from DB to anywhere — DB never initiates outbound by design.",
    "WEB initiating to DB on any port — bypasses application tier (lateral movement).",
    "APP initiating to WEB on any port — reverse direction, indicates APP compromise.",
    "WEB or APP initiating to MGT on any port — escalation attempt toward management plane.",
]


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


def render_for_prompt() -> str:
    parts: list[str] = ["## PRODUCTION TRAFFIC BASELINES\n"]
    parts.append(
        f"Steady-state east-west volume: ~{STEADY_STATE_FLOWS_PER_MINUTE} flows/minute. "
        f"MGT audit emissions ~{MGT_AUDIT_ALERT_RATE_PER_MINUTE}/minute (SID 9000020) are "
        "REQUIRED VISIBILITY, not incidents.\n"
    )
    parts.append("### Application traffic (business workload)\n")
    for p in APPLICATION_FLOWS:
        parts.append(
            f"- **{p.name}**: {p.src_ip} → {p.dst_ip}:{p.dst_port}/{p.proto}, {p.cadence}, "
            f"~{p.expected_volume_per_hour}/hr, criticality={p.criticality_to_business.value}\n"
            f"  - {p.production_description}\n"
            f"  - Anomaly trigger: {p.burst_anomaly_threshold}\n"
            f"  - If disrupted: {p.if_disrupted}"
        )

    parts.append("\n### Management plane traffic (audit/scrape/logpull)\n")
    for p in MANAGEMENT_FLOWS:
        parts.append(
            f"- **{p.name}**: {p.src_ip} → {p.dst_ip}:{p.dst_port}/{p.proto}, {p.cadence}, "
            f"criticality={p.criticality_to_business.value}\n"
            f"  - {p.production_description}\n"
            f"  - If disrupted: {p.if_disrupted}"
        )

    parts.append("\n### Anomalous patterns (NOT in baseline — red flags)\n")
    for s in ANOMALOUS_PATTERNS:
        parts.append(f"- {s}")

    return "\n".join(parts)
