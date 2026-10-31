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

# Agent-allowed actions:
#   DROP     — push enforce rule (P1/P2 threat-grade decisions)
#   log_only — record decision in audit trail, NO rule pushed (P3/P4 baseline observations)
# ACCEPT/RETURN/REJECT are policy expansion — escalate to operator (OU=sdnc).
# Source-of-truth: knowledge/infra/invariants.md → loaded via core.invariants.
try:
    from ...core.invariants import ALLOWED_AGENT_ACTIONS as _KG_ALLOWED
    ALLOWED_AGENT_ACTIONS: frozenset[str] = frozenset(_KG_ALLOWED)
except Exception:
    # Fail-closed fallback: if KG load failed, allow only DROP (legacy behavior).
    ALLOWED_AGENT_ACTIONS = frozenset({"DROP"})

# The authored invariant list (knowledge_v2/infra/invariants.md — MGT/MON hosts, LEAF
# mgmt, IDS) is merged in. Union only: the knowledge base can add protected ranges but
# never remove the hard-coded ones above.
try:
    from ...core.invariants import NEVER_BLOCK_CIDRS as _KG_NEVER_BLOCK
    NEVER_BLOCK = NEVER_BLOCK + [c for c in _KG_NEVER_BLOCK if c not in NEVER_BLOCK]
except Exception:
    pass

_NEVER_BLOCK_NETS = [ipaddress.ip_network(cidr, strict=False) for cidr in NEVER_BLOCK]


def is_protected_ip(ip: str) -> bool:
    """Return True if the IP falls within NEVER_BLOCK ranges."""
    bare = ip.split("/")[0]
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return False
    return any(addr in net for net in _NEVER_BLOCK_NETS)


def check_never_block(src_ip: str, dst_ip: str = "", source_scoped: bool = True) -> str | None:
    """
    Return error string if the rule would isolate a protected asset. None if safe.
    This is a HARD FAIL — caller must halt enforcement on non-None return.

    I3 forbids isolating a protected asset, which is a property of the rule's SOURCE: a
    source-scoped rule `-s S/32 -d D` only drops connections S initiates towards D. It
    leaves everything D initiates untouched (the leaf accepts ESTABLISHED/RELATED first),
    so it does not isolate D. Rejecting such a rule because D is protected would instead
    forbid containing unauthorised access *to* the management plane — the very condition
    SID 9000011 reports. The destination is therefore only rejected for rules that are not
    source-scoped, where dropping towards D could cut D off wholesale.
    """
    if is_protected_ip(src_ip):
        return f"L4 HARD FAIL: src_ip {src_ip} is in NEVER_BLOCK whitelist"
    if dst_ip and is_protected_ip(dst_ip) and not source_scoped:
        return f"L4 HARD FAIL: dst_ip {dst_ip} is in NEVER_BLOCK whitelist (rule not source-scoped)"
    return None


def check_allowed_action(action: str) -> str | None:
    """Return error string if action is not in ALLOWED_AGENT_ACTIONS."""
    if action not in ALLOWED_AGENT_ACTIONS:
        return (
            f"L4 HARD FAIL: action '{action}' not in allowed set {ALLOWED_AGENT_ACTIONS}. "
            "Agent may only issue DROP rules."
        )
    return None
