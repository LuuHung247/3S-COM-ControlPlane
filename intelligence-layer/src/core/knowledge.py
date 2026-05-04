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
    9000006: {
        "severity": 1,
        "desc": "APP direct access to DB (lateral movement)",
        "tactic": "TA0008 Lateral Movement",
        "technique": "T1021 Remote Services",
        "action": "block",
        "ttl": 3600,
        "flow": "APP → DB",
    },
    9000003: {
        "severity": 2,
        "desc": "APP reverse call to WEB (unexpected flow)",
        "tactic": "TA0008 Lateral Movement",
        "technique": "T1021 Remote Services",
        "action": "block",
        "ttl": 1800,
        "flow": "APP → WEB",
    },
    9000004: {
        "severity": 2,
        "desc": "WEB to MGT privilege escalation",
        "tactic": "TA0004 Privilege Escalation",
        "technique": "T1078 Valid Accounts",
        "action": "block",
        "ttl": 1800,
        "flow": "WEB → MGT",
    },
    9000005: {
        "severity": 2,
        "desc": "APP to MGT privilege escalation",
        "tactic": "TA0004 Privilege Escalation",
        "technique": "T1078 Valid Accounts",
        "action": "block",
        "ttl": 1800,
        "flow": "APP → MGT",
    },
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
}


def get_sid_info(sid: int) -> dict | None:
    return SID_KNOWLEDGE.get(sid)


def render_sid_knowledge() -> str:
    lines = ["Known Suricata SIDs and MITRE mappings:"]
    for sid, info in SID_KNOWLEDGE.items():
        lines.append(
            f"  SID {sid} (P{info['severity']}): {info['desc']}"
            f" | {info['tactic']} / {info['technique']}"
            f" | action={info['action']}"
        )
    return "\n".join(lines)
