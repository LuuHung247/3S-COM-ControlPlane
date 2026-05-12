"""Zone-to-zone policy matrix. Pure logic, no I/O.

Authoring source: knowledge/infra/policy-matrix.md
Bootstrap path:   .md → knowledge_parser → POLICY_MATRIX (at import time)
Runtime path:     replaced in-place at app startup by Neo4j read.
"""
from .topology import ip_to_zone
from . import knowledge_parser as _kp

POLICY_MATRIX: dict[tuple[str, str], str] = _kp.parse_policy_matrix()


def check_policy(src_zone: str, dst_zone: str) -> str:
    """Return 'ALLOW' or 'DENY' for the given zone pair."""
    return POLICY_MATRIX.get((src_zone, dst_zone), "DENY")


def detect_conflict(
    src_ip: str,
    dst_ip: str,
    action: str,
    sid: int | None = None,
) -> str | None:
    """
    Return an error string if proposed action contradicts policy matrix, else None.

    A DROP on an ALLOW flow is normally flagged as a conflict (would break legitimate
    traffic). EXCEPTION: when the firing SID is an anomaly-on-baseline detector whose
    catalogued recommended_response is also DROP, the override is intentional — the
    static policy matrix says "this zone pair is allowed", but the SID-specific KG
    knows that on THIS path a behavioural threshold was crossed and DROP is the
    catalogued response. Without this exception the agent could never enforce against
    ALLOW-path anomalies (SIDs 9000030-9000035), defeating the purpose of behavioural
    detection on baseline flows.
    """
    src_zone = ip_to_zone(src_ip)
    dst_zone = ip_to_zone(dst_ip)
    if src_zone is None or dst_zone is None:
        return None  # Unknown zone — let safety layers handle
    policy = check_policy(src_zone, dst_zone)
    if action == "DROP" and policy == "ALLOW":
        # Allow agent to override the static ALLOW when the SID itself catalogues
        # DROP as its recommended response (behavioural anomaly on a baseline path).
        if sid is not None:
            from . import threat_playbook
            det = threat_playbook.SID_DETECTIONS.get(sid)
            if det and det.recommended_response and "DROP" in det.recommended_response.upper():
                return None
        return (
            f"Conflict: {src_zone}→{dst_zone} is ALLOW in policy matrix "
            f"but proposed action is DROP (would break legitimate traffic)"
        )
    return None


def render_policy_matrix() -> str:
    lines = ["Zone-to-zone policy matrix:"]
    for (src, dst), verdict in POLICY_MATRIX.items():
        lines.append(f"  {src} → {dst}: {verdict}")
    return "\n".join(lines)
