"""L4: Hard guardrails — immutable whitelist. NEVER_BLOCK must never be modified at runtime."""
import ipaddress

# Addresses that the agent MUST NEVER block under any circumstances.
# Blocking these would sever control-plane access to the datacenter.
NEVER_BLOCK: list[str] = [
    "127.0.0.0/8",         # loopback
    "10.10.6.0/24",        # GNS3VM management plane
    "192.168.122.0/24",    # LEAF NETCONF/gNMI control plane
    "10.1.100.1/32",       # LEAF-1 SVI WEB gateway
    "10.1.200.1/32",       # LEAF-1 SVI DB gateway
    "10.2.100.1/32",       # LEAF-2 SVI APP gateway
    "10.2.50.1/32",        # LEAF-2 SVI MGT gateway
]

# Only DROP is allowed for agent-enforced rules.
# ACCEPT/RETURN would be policy expansion, which intelligence-layer never does.
ALLOWED_AGENT_ACTIONS: frozenset[str] = frozenset({"DROP"})

_NEVER_BLOCK_NETS = [ipaddress.ip_network(cidr, strict=False) for cidr in NEVER_BLOCK]


def is_protected_ip(ip: str) -> bool:
    """Return True if the IP falls within NEVER_BLOCK ranges."""
    bare = ip.split("/")[0]
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return False
    return any(addr in net for net in _NEVER_BLOCK_NETS)


def check_never_block(src_ip: str, dst_ip: str = "") -> str | None:
    """
    Return error string if src_ip or dst_ip is protected. None if safe.
    This is a HARD FAIL — caller must halt enforcement on non-None return.
    """
    if is_protected_ip(src_ip):
        return f"L4 HARD FAIL: src_ip {src_ip} is in NEVER_BLOCK whitelist"
    if dst_ip and is_protected_ip(dst_ip):
        return f"L4 HARD FAIL: dst_ip {dst_ip} is in NEVER_BLOCK whitelist"
    return None


def check_allowed_action(action: str) -> str | None:
    """Return error string if action is not in ALLOWED_AGENT_ACTIONS."""
    if action not in ALLOWED_AGENT_ACTIONS:
        return (
            f"L4 HARD FAIL: action '{action}' not in allowed set {ALLOWED_AGENT_ACTIONS}. "
            "Agent may only issue DROP rules."
        )
    return None
