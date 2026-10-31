"""SID → MITRE ATT&CK mapping. Hardcoded from DATAPLANE.md — no tool call needed."""

SID_KNOWLEDGE: dict[int, dict] = {
    9000001: {
        "severity": 1,
        "desc": "WEB direct access to DB (lateral movement)",
        "tactic": "TA0008 Lateral Movement",
        "technique": "T1021 Remote Services",
        "action": "block",
        "ttl": 3600,
        "flow": "WEB → DB",
    },
    9000002: {
        "severity": 1,
        "desc": "DB initiating outbound connection (exfiltration)",
        "tactic": "TA0010 Exfiltration",
        "technique": "T1041 Exfiltration Over C2 Channel",
        "action": "block",
        "ttl": 3600,
        "flow": "DB → external",
    },
    # SID 9000006 (APP→DB direct) intentionally absent — APP→DB is an ALLOWED
    # legitimate path per policy matrix (application tier queries database). A rule
    # firing on this flow would create false-positive alerts on baseline traffic
    # (app-to-database-oltp baseline, ~120/hour). See DATAPLANE.md §7.2.
    # SIDs 9000003, 9000004, 9000005 removed in 2026-05-09 refactor — all DENY-path
    # violations that LEAF zt-default-drop already blocks (agent rule would be redundant).
    # Replaced by ALLOW-path anomaly SIDs 9000030-9000035 below.
    9000010: {
        "severity": 3,
        "desc": "ICMP ping sweep (reconnaissance)",
        "tactic": "TA0043 Reconnaissance",
        "technique": "T1018 Remote System Discovery",
        "action": "log_only",
        "ttl": 0,
        "flow": "any",
    },
    9000011: {
        "severity": 3,
        "desc": "TCP port scan (reconnaissance)",
        "tactic": "TA0043 Reconnaissance",
        "technique": "T1046 Network Service Discovery",
        "action": "log_only",
        "ttl": 0,
        "flow": "any",
    },
    9000020: {
        "severity": 4,
        "desc": "MGT zone access audit event",
        "tactic": "TA0007 Discovery",
        "technique": "T1082 System Information Discovery",
        "action": "log_only",
        "ttl": 0,
        "flow": "MGT",
    },
    # ─── East-West Behavioral Anomalies (ALLOW-path abuse — agent essential) ──
    9000030: {
        "severity": 2,
        "desc": "WEB→APP connection rate burst (compromised web-tier?)",
        "tactic": "TA0040 Impact",
        "technique": "T1499 Endpoint Denial of Service",
        "action": "block_targeted",
        "ttl": 1800,
        "flow": "WEB → APP",
    },
    9000031: {
        "severity": 2,
        "desc": "APP→DB volume anomaly (possible data exfiltration)",
        "tactic": "TA0010 Exfiltration",
        "technique": "T1041 Exfiltration Over C2 Channel",
        "action": "block_targeted",
        "ttl": 1800,
        "flow": "APP → DB",
    },
    9000032: {
        "severity": 2,
        "desc": "DB→APP large reply payload (bulk SELECT extraction)",
        "tactic": "TA0009 Collection",
        "technique": "T1567 Exfiltration to Cloud Storage (adapted)",
        "action": "block_targeted",
        "ttl": 1800,
        "flow": "DB → APP",
    },
    9000033: {
        "severity": 1,
        "desc": "Destructive SQL pattern (DROP TABLE / TRUNCATE)",
        "tactic": "TA0040 Impact",
        "technique": "T1485 Data Destruction",
        "action": "block_targeted_escalate",
        "ttl": 3600,
        "flow": "APP → DB",
    },
    9000034: {
        "severity": 3,
        "desc": "APP→DB time-window context probe (agent evaluates off-hours)",
        "tactic": "TA0001 Initial Access",
        "technique": "T1078 Valid Accounts (off-hours abuse)",
        "action": "agent_time_eval",
        "ttl": 900,
        "flow": "APP → DB",
    },
    9000035: {
        "severity": 1,
        "desc": "Cross-tier SSH (workload-to-workload lateral movement)",
        "tactic": "TA0008 Lateral Movement",
        "technique": "T1021.004 Remote Services - SSH",
        "action": "block_targeted_flag_host",
        "ttl": 3600,
        "flow": "WEB/APP → WEB/APP/DB:22",
    },
}


def get_sid_info(sid: int) -> dict | None:
    """SID metadata for L6 gating + prompt context.

    V2: derive from the live threat_playbook catalog (loaded from knowledge_v2 →
    Neo4j hot-swap), NOT the legacy hardcoded SID_KNOWLEDGE table above (which was
    V1-only and had stale severities/semantics — e.g. 9000011 was "TCP port scan
    P3" in V1 but is "inbound-to-MGT P1" in V2). Single source of truth = the KB.
    Deferred import avoids a circular dependency at module load.
    """
    from .threat_playbook import get_sid_detection
    det = get_sid_detection(sid)
    if det is None:
        return None
    sev = det.severity_p_level
    return {
        "severity": sev,
        "desc": det.signature_msg,
        "tactic": det.mitre_tactic,
        "technique": det.mitre_technique,
        "detection_logic": det.detection_logic,
        # action/ttl derived from severity (P1/P2 enforce, P3/P4 log_only) — matches
        # the L6 _SEVERITY_RULES gradation; V2 catalog leaves recommended_response blank.
        "action": "block" if sev <= 2 else "log_only",
        "ttl": 3600 if sev == 1 else (1800 if sev == 2 else 0),
        "false_positive_likelihood": det.false_positive_likelihood,
    }


def render_sid_knowledge() -> str:
    from .threat_playbook import SID_DETECTIONS
    lines = ["Known Suricata SIDs and MITRE mappings:"]
    for sid, det in SID_DETECTIONS.items():
        lines.append(
            f"  SID {sid} (P{det.severity_p_level}): {det.signature_msg}"
            f" | {det.mitre_tactic} / {det.mitre_technique}"
        )
    return "\n".join(lines)
