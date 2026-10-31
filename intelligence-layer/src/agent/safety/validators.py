"""L1+L3+L6: Schema, topology, policy conflict, and action-gradation validators."""
import ipaddress

from ...models.decision import PolicyIntent, PolicyAction
from ...core.topology import ip_to_zone
from ...core.policy import detect_conflict
from ...core.knowledge import get_sid_info
from .guardrails import is_protected_ip, check_never_block, check_allowed_action


# L6: severity → allowed action + default TTL.
# log_only is ALWAYS permitted (the safe, no-enforcement fallback): a P1/P2 SID
# firing on traffic the agent reasons is legitimate (false positive) MUST be able
# to resolve as log_only — otherwise FP-control is impossible (the agent would be
# forced to over-block, or have its correct log_only spuriously rejected). The
# gradation only CAPS aggression: P3/P4 may NOT DROP (log_only only).
_SEVERITY_RULES: dict[int, dict] = {
    1: {"allowed_actions": {"DROP", "log_only"}, "ttl_min": 60, "ttl_max": 3600},
    2: {"allowed_actions": {"DROP", "log_only"}, "ttl_min": 60, "ttl_max": 1800},
    3: {"allowed_actions": {"log_only"}, "ttl_min": 0, "ttl_max": 0},
    4: {"allowed_actions": {"log_only"}, "ttl_min": 0, "ttl_max": 0},
}


class ValidationResult:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.semantic_override = False

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0

    def fail(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def _ip_matches_alert_src(intent_src_ip: str, alert_src_ip: str) -> bool:
    """L4b: intent.src_ip must be exactly alert.src_ip (/32) — prevents off-target enforcement
    from LLM hallucination or prompt injection nudging a different IP."""
    if not alert_src_ip:
        return False
    try:
        alert_addr = ipaddress.ip_address(alert_src_ip.strip().split("/")[0])
        intent_net = ipaddress.ip_network(intent_src_ip.strip(), strict=False)
        # Target fidelity (I2) is exact: the rule must name the alert source host only.
        # A wider CIDR that merely contains the source would isolate its neighbours too.
        return intent_net.num_addresses == 1 and alert_addr in intent_net
    except (ValueError, TypeError):
        return False


SEMANTIC_OVERRIDE_MIN_CONFIDENCE = 0.90
SEMANTIC_OVERRIDE_TTL_MAX = 1800


def _semantic_override_admissible(intent: PolicyIntent, alert_severity: int) -> bool:
    flow_scope = bool((intent.dst_ip or "").split("/")[0]) and int(intent.dst_port or 0) > 0
    return (intent.action == PolicyAction.DROP and flow_scope
            and intent.confidence >= SEMANTIC_OVERRIDE_MIN_CONFIDENCE
            and alert_severity in (1, 2))


def validate_intent(
    intent: PolicyIntent,
    sid: int,
    ttl_min: int,
    ttl_max: int,
    alert_src_ip: str = "",
    alert_dst_ip: str = "",
    alert_severity: int = 4,
    alert_initiator_ip: str = "",
) -> ValidationResult:
    result = ValidationResult()

    # L1: Schema — Pydantic already validated types; check string lengths.
    # Note: reasoning_steps populate in V3 Stage 2 (parallel with enforce), so
    # validator runs before reasoning is available. Empty here is expected and OK.
    if intent.comment and len(intent.comment) < 10:
        result.warn("L1: comment is very short — may indicate shallow reasoning")

    # L4: Hard guardrails (CRITICAL — must check before anything else)
    # Agent rules are always source-scoped: I2 below requires src_ip to be the alert
    # source as a single host, so the rule cannot isolate the destination.
    nb_err = check_never_block(intent.src_ip, intent.dst_ip, source_scoped=True)
    if nb_err:
        result.fail(nb_err)

    action_err = check_allowed_action(intent.action.value)
    if action_err:
        result.fail(action_err)

    # L4b: Off-target enforcement check — only meaningful for DROP rules,
    # log_only doesn't push a rule so IP mismatch is not security-critical.
    if intent.action == PolicyAction.DROP and alert_src_ip:
        if not _ip_matches_alert_src(intent.src_ip, alert_src_ip):
            result.fail(
                f"L4b OFF-TARGET: intent.src_ip={intent.src_ip!r} does not contain "
                f"alert.src_ip={alert_src_ip!r}. Possible LLM hallucination or prompt injection."
            )

    # L4c: responder check. EVE flow.src_ip is the connection initiator; an alert raised on
    # reply packets names the responder as src. Never punish a host for answering a
    # protected/management initiator, and never widen beyond the flow for a responder.
    initiator = (alert_initiator_ip or "").split("/")[0]
    if intent.action == PolicyAction.DROP and initiator and alert_src_ip and initiator != alert_src_ip.split("/")[0]:
        if is_protected_ip(initiator):
            result.fail(f"L4c RESPONDER: {alert_src_ip} is answering a connection initiated by "
                        f"protected host {initiator}")
        elif not (intent.dst_ip or "").split("/")[0] or not int(intent.dst_port or 0):
            result.fail(f"L4c RESPONDER: {alert_src_ip} is the responder of a flow initiated by "
                        f"{initiator}; only flow scope is admissible")

    if not result.ok:
        return result  # Short-circuit on L4 failures

    # L3: Topology check
    src_zone = ip_to_zone(intent.src_ip)
    if src_zone is None:
        result.fail(f"L3: src_ip {intent.src_ip} not in any known zone")

    # L3: Policy conflict (passes SID so SID-catalogued DROP can override ALLOW path)
    # A host-scope rule (empty dst_ip) is checked against the alert's own flow, so
    # widening scope cannot bypass the conflict check on a permitted path.
    conflict_dst = intent.dst_ip or alert_dst_ip
    if conflict_dst:
        conflict = detect_conflict(intent.src_ip, conflict_dst, intent.action.value, sid=sid)
        if conflict and _semantic_override_admissible(intent, alert_severity):
            # Bounded semantic override on a permitted path: content/behaviour evidence
            # judged malicious by the model. Narrowest scope only, high confidence,
            # severe IDS alert, shortened TTL; rate-limited by the caller.
            intent.ttl_seconds = min(intent.ttl_seconds, SEMANTIC_OVERRIDE_TTL_MAX)
            result.semantic_override = True
            result.warn(f"L3-SO: semantic override of permitted path ({conflict})")
        elif conflict:
            result.fail(f"L3: {conflict}")

    # L6: Action gradation by severity
    sid_info = get_sid_info(sid)
    if sid_info is not None:
        severity = sid_info["severity"]
        severity_rule = _SEVERITY_RULES.get(severity, {})
        allowed = severity_rule.get("allowed_actions", set())
        if intent.action.value not in allowed:
            result.fail(
                f"L6: SID {sid} severity={severity} only allows actions={allowed}, "
                f"got action={intent.action.value}"
            )
        # P3/P4: should not push a rule at all — log_only means no enforcement
        if severity >= 3 and intent.action == PolicyAction.DROP:
            result.fail(
                f"L6: Severity P{severity} (SID {sid}) must be log_only, not DROP"
            )

    # L5: TTL range
    if intent.action == PolicyAction.DROP:
        if intent.ttl_seconds < ttl_min or intent.ttl_seconds > ttl_max:
            result.fail(
                f"L5: ttl_seconds={intent.ttl_seconds} out of range [{ttl_min}, {ttl_max}]"
            )

    return result
