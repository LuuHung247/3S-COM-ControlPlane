"""Zone-to-zone policy matrix. Pure logic, no I/O.

Authoring source: knowledge/infra/policy-matrix.md
Bootstrap path:   .md → knowledge_parser → POLICY_MATRIX (at import time)
Runtime path:     replaced in-place at app startup by Neo4j read.
"""
from .topology import ip_to_zone
from . import knowledge_parser as _kp

POLICY_MATRIX: dict[tuple[str, str], str] = _kp.parse_policy_matrix()

# V2 ALLOW-path anomaly detectors — SIDs that fire on CONTENT/BEHAVIOURAL abuse inside
# a policy-legal connection (so a DROP on their ALLOW path is an intentional override).
#   9000050-52 volumetric (SYN/UDP flood) · 9000060-62 C2/exfil · 9000070-72 SQL content
_ALLOW_PATH_ANOMALY_SIDS: frozenset[int] = frozenset(
    {9000050, 9000051, 9000052, 9000060, 9000061, 9000062, 9000070, 9000071, 9000072}
)


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
    knows that on THIS path a content/behavioural threshold was crossed and a DROP is
    warranted. Without this exception the agent could never enforce against ALLOW-path
    abuse (SQL injection/destructive SQL, C2/exfil, volumetric), defeating the purpose
    of behavioural + content detection on baseline flows.
    """
    src_zone = ip_to_zone(src_ip)
    dst_zone = ip_to_zone(dst_ip)
    if src_zone is None or dst_zone is None:
        return None  # Unknown zone — let safety layers handle
    policy = check_policy(src_zone, dst_zone)
    if action == "DROP" and policy == "ALLOW":
        # Allow the agent to override the static ALLOW when the firing SID is an
        # ALLOW-path anomaly detector — content (SQL: 9000070-72), C2/exfil
        # (9000060-62), or volumetric (9000050-52). These fire WITHIN a policy-legal
        # connection, so a DROP is an intentional behavioural override, not a mistaken
        # block of legitimate traffic. (V1 used 9000030-35; V2 catalog leaves
        # recommended_response blank, so we key on the detector class by SID.)
        if sid is not None and sid in _ALLOW_PATH_ANOMALY_SIDS:
            return None
        # Fallback: honour an explicit catalogued DROP recommendation if present.
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
