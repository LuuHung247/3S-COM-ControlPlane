"""Enforcement plane contract — Secure Framework REST API semantics for the agent.

Agent's mental model of HOW to act on the system. This describes the SF REST contract,
gotchas, failure modes, and observability — production language, not API doc.

Source of truth: knowledge/02-SECURE-FRAMEWORK.md
"""
from pydantic import BaseModel


class FailureMode(BaseModel):
    name: str
    trigger: str
    rest_status: str
    body_signature: str
    state: str
    agent_action: str


# ─────────────────────────────────────────────────────────────────────────────
# Enforcement plane data — populated from knowledge/infra/enforcement-plane.md.
#
# Authoring source: knowledge/infra/enforcement-plane.md
# Bootstrap path:   .md → knowledge_parser → these vars (at import time)
# Runtime path:     replaced in-place at app startup by Neo4j read.
# ─────────────────────────────────────────────────────────────────────────────
from . import knowledge_parser as _kp

_ep_data = _kp.parse_enforcement_plane()
ENDPOINT_CONTRACTS: dict[str, str] = dict(_ep_data["endpoint_contracts"])
FIELD_NAME_MAPPING: list[dict[str, str]] = list(_ep_data["field_name_mapping"])
CRITICAL_GOTCHAS: list[str] = list(_ep_data["critical_gotchas"])
FAILURE_MODES: list[FailureMode] = [FailureMode(**fm) for fm in _ep_data["failure_modes"]]
RBAC_CONTRACT: str = "\n" + _ep_data["rbac_contract"] + "\n"

# Legacy literal definitions removed. Edit knowledge/infra/enforcement-plane.md instead.


def render_for_prompt() -> str:
    """Full enforcement plane render — startup / KG visualization."""
    parts: list[str] = ["## ENFORCEMENT PLANE — Secure Framework Contract\n"]

    parts.append(
        "Agent uses SF REST API as single source of truth. NO SSH to LEAFs, NO direct gNMI, "
        "NO Redis/iptables access. SF endpoint: `http://ids-agent:8766/...` (proxied through "
        "ids-agent which forwards to SF).\n"
    )
    parts.append("### Endpoints in scope\n")
    for ep, desc in ENDPOINT_CONTRACTS.items():
        parts.append(f"- **{ep}**: {desc}")
    parts.append("\n### RBAC\n" + RBAC_CONTRACT.strip())
    parts.append("\n### Critical gotchas\n")
    for g in CRITICAL_GOTCHAS:
        parts.append(f"- {g}")
    parts.append("\n### Failure modes & agent recovery\n")
    for fm in FAILURE_MODES:
        parts.append(
            f"- **{fm.name}**: trigger={fm.trigger} → status {fm.rest_status}, body `{fm.body_signature}`. "
            f"State: {fm.state}. Agent action: {fm.agent_action}"
        )
    return "\n".join(parts)


def render_summary() -> str:
    """Compact enforcement contract for per-alert prompts. Just gotchas + RBAC + key
    endpoints, no failure mode walkthroughs (those rarely apply per alert)."""
    parts: list[str] = ["## ENFORCEMENT PLANE (summary)\n"]
    parts.append(
        "Single source of truth: SF REST via `http://ids-agent:8766`. "
        "Push: `POST /rules` (returns 201, sync — when 201 received rule is on iptables). "
        "Revoke: `DELETE /rules/{id}` (idempotent). "
        "Verify: `GET /rules/{id}`."
    )
    parts.append("\n### RBAC (must obey)\n" + RBAC_CONTRACT.strip())
    parts.append("\n### Critical gotchas (must obey)\n")
    for g in CRITICAL_GOTCHAS:
        parts.append(f"- {g}")
    return "\n".join(parts)
