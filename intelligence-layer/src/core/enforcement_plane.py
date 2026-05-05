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
# Endpoint contracts (the 4 endpoints the agent uses)
# ─────────────────────────────────────────────────────────────────────────────
ENDPOINT_CONTRACTS: dict[str, str] = {
    "POST /api/rules": (
        "Push a new rule. Synchronous — when 201 returns, rule is on iptables (or failure). "
        "Required body fields: rule_id (regex `[a-zA-Z0-9_\\-]{1,64}`), action (must be DROP for "
        "AGENT role). Optional: src_ip/dst_ip (CIDR), protocol (default 'all'), src_port/dst_port "
        "(only for tcp/udp), priority (default 1000 — DANGEROUS, use 50), comment, ttl_seconds "
        "(stored but NOT enforced — agent must DELETE manually). "
        "Response 201 with `errors[]` indicates partial success on cross-leaf push — check "
        "errors even on success. POST same rule_id twice = REPLACE atomically (no 409). "
        "Server overrides: source forced to 'agent', comment auto-stamped if empty."
    ),
    "GET /api/rules": (
        "List active rules from ALL LEAF nodes — live gNMI Get, no cache. Returns "
        "{leaves: {leaf-1: {connected, rules}, leaf-2: {...}}}. Field names are YANG-style "
        "(src-prefix, dst-prefix, rule-id with hyphens). Use to verify post-push state and "
        "detect partial application (rule on LEAF-1 but missing on LEAF-2)."
    ),
    "GET /api/rules/{rule_id}": (
        "Single rule status with per-LEAF presence. Returns 404 if rule not in any LEAF. "
        "Authoritative answer to 'is my rule actually active?'."
    ),
    "DELETE /api/rules/{rule_id}": (
        "Revoke rule from all LEAFs. Idempotent — DELETE non-existent returns 200 with "
        "deleted_from=[]. Always safe to retry."
    ),
    "GET /health": (
        "SF liveness probe. {status, service, mode}. Use before high-cost actions."
    ),
    "GET /pool": (
        "SF→LEAF connection pool status. Check connections.admin=true for both leaves "
        "before cross-leaf rule push."
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Field name mapping (most common confusion source)
# ─────────────────────────────────────────────────────────────────────────────
FIELD_NAME_MAPPING: list[dict[str, str]] = [
    {"rest_request": "rule_id or rule-id", "yang_gnmi": "rule-id", "configdb": "key"},
    {"rest_request": "action", "yang_gnmi": "action", "configdb": "action"},
    {"rest_request": "src_ip or src-ip", "yang_gnmi": "src-ip", "configdb": "src-prefix ⚠️"},
    {"rest_request": "dst_ip or dst-ip", "yang_gnmi": "dst-ip", "configdb": "dst-prefix ⚠️"},
    {"rest_request": "protocol", "yang_gnmi": "protocol", "configdb": "protocol"},
    {"rest_request": "src_port", "yang_gnmi": "src-port", "configdb": "src-port"},
    {"rest_request": "dst_port", "yang_gnmi": "dst-port", "configdb": "dst-port"},
    {"rest_request": "priority", "yang_gnmi": "priority", "configdb": "priority"},
    {"rest_request": "source", "yang_gnmi": "source", "configdb": "source"},
    {"rest_request": "ttl_seconds", "yang_gnmi": "ttl-seconds", "configdb": "ttl-seconds"},
]


# ─────────────────────────────────────────────────────────────────────────────
# Critical gotchas
# ─────────────────────────────────────────────────────────────────────────────
CRITICAL_GOTCHAS: list[str] = [
    (
        "PRIORITY GOTCHA: priority >= 1000 (default) causes `iptables -A FORWARD` (append) — "
        "rule lands AFTER `nos:zt-default-drop` and is silently ineffective. "
        "Agent block rules MUST use priority=50 (or any value <100, which translates to "
        "`iptables -I FORWARD 1`)."
    ),
    (
        "TTL NOT ENFORCED: ttl_seconds is stored but no background expiration runs. "
        "Agent maintains its own {rule_id → expire_at} map and calls DELETE when expired. "
        "Idempotent DELETE — safe to retry."
    ),
    (
        "AGENT ROLE = DROP ONLY: SF outbound cert has OU=auto. Bridge enforces AGENT role: "
        "action MUST be DROP, source forced to 'agent'. Agent gửi action=ACCEPT → HTTP 400 "
        "'AGENT role may only push DROP rules' from adapter."
    ),
    (
        "FIELD NAME DRIFT: POST request accepts both src_ip and src-ip. GET response uses "
        "YANG-style src-prefix in ConfigDB and src-ip in gNMI notification. Parse code MUST "
        "handle both forms."
    ),
    (
        "PARTIAL FAILURE ON CROSS-LEAF: HTTP 201 with errors[] non-empty means rule applied to "
        "subset of LEAFs (e.g., LEAF-1 ok, LEAF-2 timeout). Defense-in-depth broken. Default "
        "policy: rollback DELETE and retry once both leaves connected."
    ),
    (
        "SOURCE SEMANTICS WIN: source field is server-overwritten to 'agent' in current cert "
        "configuration (OU=auto). What client sends in body is irrelevant — provenance is "
        "decided by SF outbound cert."
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Failure modes & recovery
# ─────────────────────────────────────────────────────────────────────────────
FAILURE_MODES: list[FailureMode] = [
    FailureMode(
        name="gnmi-timeout-all-leaves",
        trigger="Both LEAF mgmt unreachable",
        rest_status="500",
        body_signature="{success:false, error:'<host>: deadline exceeded'}",
        state="No rule applied anywhere",
        agent_action="Retry with exponential backoff (60s, 300s). After 3 retries, escalate. NEVER SSH to LEAF.",
    ),
    FailureMode(
        name="gnmi-timeout-partial",
        trigger="One LEAF mgmt unreachable during cross-leaf push",
        rest_status="201 (partial success)",
        body_signature="{success:true, pushed_to:['ip1'], errors:['ip2: ...']}",
        state="Rule applied on one LEAF only — defense-in-depth gap",
        agent_action="Default: rollback via DELETE then retry when both leaves up. Alternative: accept partial if source-leaf rule already blocks the threat.",
    ),
    FailureMode(
        name="bridge-validator-reject",
        trigger="Schema invalid, AGENT push non-DROP, source mismatch",
        rest_status="400",
        body_signature="{success:false, error:'<validator message>'}",
        state="Atomic — no rule applied",
        agent_action="DETERMINISTIC reject. Do NOT retry. Fix the rule construction or escalate.",
    ),
    FailureMode(
        name="agent-role-non-drop",
        trigger="Agent submitted action=ACCEPT or RETURN",
        rest_status="400",
        body_signature="{success:false, error:'AGENT role may only push DROP rules'}",
        state="No rule applied",
        agent_action="Code bug — agent should never construct non-DROP. Escalate as defect.",
    ),
    FailureMode(
        name="duplicate-rule-id",
        trigger="POST same rule_id twice",
        rest_status="201",
        body_signature="{success:true} — REPLACE semantics, not 409",
        state="Old rule replaced atomically with new field values",
        agent_action="No action needed — REPLACE is intentional. Use deterministic rule_id (sha256 of flow tuple) to dedupe.",
    ),
    FailureMode(
        name="sf-unreachable",
        trigger="SF process down, network partition between agent and SF",
        rest_status="ConnectionError (no HTTP response)",
        body_signature="N/A",
        state="UNKNOWN — agent cannot determine if rule is active",
        agent_action="ESCALATE IMMEDIATELY. Agent has NO fallback path — single source of truth invariant.",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# RBAC — only 2 cert OUs the agent needs to know about
# ─────────────────────────────────────────────────────────────────────────────
RBAC_CONTRACT = """
Agent operates under cert OU=auto, role AGENT. AGENT can ONLY push DROP rules.
For ACCEPT rules (e.g., to whitelist legitimate flow), agent MUST escalate to operator
with OU=sdnc (role ADMIN). Agent cannot do this autonomously.

Defense-in-depth on enforcement plane:
1. SF adapter rejects non-DROP from AGENT role (HTTP 400)
2. nos-acl-bridge validators on each LEAF re-verify role+source
3. Both must pass — no single bypass.
"""


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
