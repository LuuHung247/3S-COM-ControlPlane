"""System and user prompts for the LangGraph agent."""
from ..models.alert import SuricataAlert
from ..core.knowledge import get_sid_info

_SYSTEM_TEMPLATE = """\
You are a Zero Trust Network Security AI agent for a datacenter microsegmentation system.
Your role: analyze Suricata IDS alerts and decide whether to enforce a DROP rule via the
Secure Framework API. You are the ONLY automated enforcement mechanism — your decisions
affect live datacenter traffic. Be precise. Be conservative. Prefer false-negatives over
false-positives.

CRITICAL CONSTRAINTS:
- You may ONLY issue DROP rules (never ACCEPT or RETURN)
- You MUST NOT block management-plane IPs or SVI gateways
- P3/P4 severity alerts → log_only (never DROP)
- Confidence < 0.70 → log and hold for manual review
- Every decision MUST include step-by-step reasoning_steps

{context_snapshot}
"""

_CLASSIFY_TEMPLATE = """\
Classify this Suricata alert as exactly one of: benign, suspicious, threat.

Alert details:
- SID: {sid}
- Signature: {signature}
- Source IP: {src_ip} (Zone: {src_zone})
- Destination IP: {dst_ip}:{dst_port} (Proto: {proto})
- Severity: P{severity}
- Category: {category}

SID context: {sid_context}

Respond with ONLY one word: benign, suspicious, or threat.
"""

_REASON_TEMPLATE = """\
Analyze this security alert and determine the appropriate enforcement action.

Alert:
- SID: {sid} | Severity: P{severity}
- Signature: {signature}
- Source: {src_ip} ({src_zone}) → Destination: {dst_ip}:{dst_port} ({dst_zone})
- Protocol: {proto}
- SID context: {sid_context}

Alert history for {src_ip}:
{alert_history}

Use the POLICY_INTENT schema to output your decision. Include clear reasoning_steps.
Your confidence must reflect your actual certainty (0.0-1.0).
"""


def build_system_prompt(context_snapshot: str) -> str:
    return _SYSTEM_TEMPLATE.format(context_snapshot=context_snapshot)


def build_classify_prompt(alert: SuricataAlert, src_zone: str | None) -> str:
    sid_info = get_sid_info(alert.sid)
    return _CLASSIFY_TEMPLATE.format(
        sid=alert.sid,
        signature=alert.signature,
        src_ip=alert.src_ip,
        src_zone=src_zone or "unknown",
        dst_ip=alert.dest_ip,
        dst_port=alert.dest_port,
        proto=alert.proto,
        severity=alert.severity,
        category=alert.category,
        sid_context=str(sid_info) if sid_info else "Unknown SID",
    )


def build_reason_prompt(
    alert: SuricataAlert,
    src_zone: str | None,
    dst_zone: str | None,
    alert_history: list[dict],
) -> str:
    sid_info = get_sid_info(alert.sid)
    history_str = "\n".join(
        f"  - SID {h.get('alert', {}).get('signature_id')} at {h.get('timestamp', '')}"
        for h in alert_history[:5]
    ) or "  No previous alerts from this IP"

    return _REASON_TEMPLATE.format(
        sid=alert.sid,
        severity=alert.severity,
        signature=alert.signature,
        src_ip=alert.src_ip,
        src_zone=src_zone or "unknown",
        dst_ip=alert.dest_ip,
        dst_port=alert.dest_port,
        dst_zone=dst_zone or "unknown",
        proto=alert.proto,
        sid_context=str(sid_info) if sid_info else "Unknown SID",
        alert_history=history_str,
    )
