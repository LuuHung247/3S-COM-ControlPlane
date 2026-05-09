"""Network invariants — rules the agent MUST NOT violate.

Hard constraints that override LLM reasoning. These are encoded as both:
1. NEVER_BLOCK list (checked in safety/guardrails.py L4)
2. Production-language statements rendered into system prompt (so LLM understands WHY)

Source of truth: knowledge/01-DATAPLANE.md §9, knowledge/02-SECURE-FRAMEWORK.md §8
"""

# ─────────────────────────────────────────────────────────────────────────────
# Invariants — populated from knowledge/infra/invariants.md at import.
#
# Authoring source: knowledge/infra/invariants.md
# Bootstrap path:   .md → knowledge_parser → these vars (at import time)
# Runtime path:     replaced in-place at app startup by Neo4j read.
#
# 🛑 SAFETY-CRITICAL: even though .md is the authoring layer, the parser fails
# closed if any expected-critical CIDR (mgt-01, IDS, SVI gateways) is missing
# — see startup validation in main.py lifespan. Mutation of Neo4j cannot weaken
# the never-block list below the safety floor.
# ─────────────────────────────────────────────────────────────────────────────
from . import knowledge_parser as _kp

_inv_data = _kp.parse_invariants()
NEVER_BLOCK_CIDRS: list[str] = list(_inv_data["never_block_cidrs"])
NEVER_BLOCK_RATIONALE: dict[str, str] = dict(_inv_data["never_block_rationale"])
ALLOWED_AGENT_ACTIONS: frozenset[str] = frozenset(_inv_data["allowed_agent_actions"])
PROTECTED_COMMENT_PREFIXES: list[str] = list(_inv_data["protected_comment_prefixes"])
AGENT_COMMENT_PREFIX: str = _inv_data["agent_comment_prefix"]

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
