"""Network invariants — rules the agent MUST NOT violate.

Hard constraints that override LLM reasoning. These are encoded as both:
1. NEVER_BLOCK list (checked in safety/guardrails.py L4)
2. Production-language statements rendered into system prompt (so LLM understands WHY)

Source of truth: knowledge/01-DATAPLANE.md §9, knowledge/02-SECURE-FRAMEWORK.md §8
"""

# ─────────────────────────────────────────────────────────────────────────────
# Hard NEVER_BLOCK list (immutable, hardcoded)
# ─────────────────────────────────────────────────────────────────────────────
NEVER_BLOCK_CIDRS: list[str] = [
    "127.0.0.0/8",          # loopback
    "192.168.122.0/24",     # mgmt OOB — block self-DoS
    "10.10.6.0/24",         # out-of-band reach to control plane
    "10.1.100.1/32",        # WEB SVI gateway
    "10.1.200.1/32",        # DB SVI gateway
    "10.2.100.1/32",        # APP SVI gateway
    "10.2.50.1/32",         # MGT SVI gateway
    "10.2.50.10/32",        # mgt-01 — kills audit/compliance/agent-vantage
    "192.168.122.205/32",   # IDS Suricata — kills agent perception
]

NEVER_BLOCK_RATIONALE: dict[str, str] = {
    "127.0.0.0/8": "Loopback addresses — blocking corrupts host networking stack",
    "192.168.122.0/24": "Management out-of-band network — agent reaches SF via this path; blocking self-DoSes the agent",
    "10.10.6.0/24": "Out-of-band reach to control plane — same rationale as above",
    "10.1.100.1/32": "WEB zone SVI gateway — blocking partitions WEB zone from rest of fabric",
    "10.1.200.1/32": "DB zone SVI gateway — blocking partitions DB zone (entire data tier offline)",
    "10.2.100.1/32": "APP zone SVI gateway — blocking partitions APP zone",
    "10.2.50.1/32": "MGT zone SVI gateway — blocking partitions management plane",
    "10.2.50.10/32": "Management host (mgt-01) — blocking kills audit, compliance, scenario controllers, and agent's vantage point",
    "192.168.122.205/32": "Suricata IDS — blocking severs agent perception of network state",
}

# ─────────────────────────────────────────────────────────────────────────────
# Allowed agent actions (frozen)
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_AGENT_ACTIONS: frozenset[str] = frozenset({"DROP"})

# ─────────────────────────────────────────────────────────────────────────────
# Comment provenance prefixes (immutable)
# ─────────────────────────────────────────────────────────────────────────────
PROTECTED_COMMENT_PREFIXES: list[str] = ["nos:zt-"]   # baseline ZT — never modify
AGENT_COMMENT_PREFIX: str = "nos:agent-"              # agent-owned rules

# ─────────────────────────────────────────────────────────────────────────────
# Priority bounds for agent rules
# ─────────────────────────────────────────────────────────────────────────────
AGENT_RULE_PRIORITY: int = 50          # < 100 → iptables -I FORWARD 1 (top-most)
PRIORITY_DANGER_FLOOR: int = 1000      # >= 1000 → append, lands AFTER default-drop


# ─────────────────────────────────────────────────────────────────────────────
# TTL bounds for agent rules
# ─────────────────────────────────────────────────────────────────────────────
TTL_MIN_SECONDS: int = 60
TTL_MAX_SECONDS: int = 3600    # 1 hour — agent should not push permanent rules


# ─────────────────────────────────────────────────────────────────────────────
# Rendered for prompt
# ─────────────────────────────────────────────────────────────────────────────
def render_for_prompt() -> str:
    parts: list[str] = ["## NETWORK INVARIANTS — HARD CONSTRAINTS\n"]

    parts.append("### NEVER_BLOCK list (hard reject if agent proposes blocking these)\n")
    for cidr in NEVER_BLOCK_CIDRS:
        parts.append(f"- `{cidr}` — {NEVER_BLOCK_RATIONALE.get(cidr, '')}")

    parts.append("\n### Hard constraints on agent actions\n")
    parts.append(
        f"- Allowed actions: {sorted(ALLOWED_AGENT_ACTIONS)}. Agent role (cert OU=auto) "
        "physically cannot push ACCEPT or RETURN — Secure Framework adapter rejects with HTTP 400."
    )
    parts.append(
        f"- Mandatory priority for block rules: **{AGENT_RULE_PRIORITY}** (or any value <100). "
        f"Priority >= {PRIORITY_DANGER_FLOOR} causes silent ineffectiveness (rule lands AFTER default-drop)."
    )
    parts.append(
        f"- TTL bounds: [{TTL_MIN_SECONDS}, {TTL_MAX_SECONDS}] seconds. Agent rules are reversible by design."
    )
    parts.append(
        f"- Comment provenance: agent rules MUST carry `{AGENT_COMMENT_PREFIX}*` prefix. "
        f"Rules with `{PROTECTED_COMMENT_PREFIXES[0]}*` (baseline ZT policy) are IMMUTABLE — agent must never modify."
    )

    parts.append("\n### Off-target enforcement check\n")
    parts.append(
        "- intent.src_ip MUST contain alert.src_ip (CIDR membership). If an LLM proposes a "
        "different src_ip than the alert source, this is treated as hallucination or prompt injection — "
        "rule rejected before push."
    )

    parts.append("\n### Single source of truth\n")
    parts.append(
        "- All state mutations and verifications go through Secure Framework REST API. "
        "If SF is unreachable → agent escalates, does NOT fallback to SSH/direct iptables."
    )

    return "\n".join(parts)
