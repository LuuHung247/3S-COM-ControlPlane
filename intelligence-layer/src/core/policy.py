"""Zone-to-zone policy matrix. Pure logic, no I/O."""
from .topology import ip_to_zone

# Explicit ALLOW/DENY per zone pair. All unlisted pairs default to DENY.
POLICY_MATRIX: dict[tuple[str, str], str] = {
    ("WEB", "DB"):  "DENY",   ("WEB", "APP"): "ALLOW", ("WEB", "MGT"): "DENY",
    ("DB",  "WEB"): "DENY",   ("DB",  "APP"): "DENY",  ("DB",  "MGT"): "DENY",
    ("APP", "WEB"): "DENY",   ("APP", "DB"):  "ALLOW", ("APP", "MGT"): "DENY",
    ("MGT", "WEB"): "ALLOW",  ("MGT", "DB"):  "ALLOW", ("MGT", "APP"): "ALLOW",
}


def check_policy(src_zone: str, dst_zone: str) -> str:
    """Return 'ALLOW' or 'DENY' for the given zone pair."""
    return POLICY_MATRIX.get((src_zone, dst_zone), "DENY")


def detect_conflict(src_ip: str, dst_ip: str, action: str) -> str | None:
    """
    Return an error string if proposed action contradicts policy matrix, else None.
    A DROP on an ALLOW flow is flagged as a conflict (would break legitimate traffic).
    """
    src_zone = ip_to_zone(src_ip)
    dst_zone = ip_to_zone(dst_ip)
    if src_zone is None or dst_zone is None:
        return None  # Unknown zone — let safety layers handle
    policy = check_policy(src_zone, dst_zone)
    if action == "DROP" and policy == "ALLOW":
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
