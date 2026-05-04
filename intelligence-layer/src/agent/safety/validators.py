"""L1+L3+L6: Schema, topology, policy conflict, and action-gradation validators."""
from ...models.decision import PolicyIntent, PolicyAction
from ...core.topology import ip_to_zone
from ...core.policy import detect_conflict
from ...core.knowledge import get_sid_info
from .guardrails import check_never_block, check_allowed_action


# L6: severity → allowed action + default TTL
_SEVERITY_RULES: dict[int, dict] = {
    1: {"allowed_actions": {"DROP"}, "ttl_min": 60, "ttl_max": 3600},
    2: {"allowed_actions": {"DROP"}, "ttl_min": 60, "ttl_max": 1800},
    3: {"allowed_actions": {"log_only"}, "ttl_min": 0, "ttl_max": 0},
    4: {"allowed_actions": {"log_only"}, "ttl_min": 0, "ttl_max": 0},
}


class ValidationResult:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0

    def fail(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def validate_intent(intent: PolicyIntent, sid: int, ttl_min: int, ttl_max: int) -> ValidationResult:
    result = ValidationResult()

    # L1: Schema — Pydantic already validated types; check string lengths
    if len(intent.reasoning_steps) == 0:
        result.fail("L1: reasoning_steps is empty — LLM must provide reasoning chain")
    if intent.comment and len(intent.comment) < 10:
        result.warn("L1: comment is very short — may indicate shallow reasoning")

    # L4: Hard guardrails (CRITICAL — must check before anything else)
    nb_err = check_never_block(intent.src_ip, intent.dst_ip)
    if nb_err:
        result.fail(nb_err)

    action_err = check_allowed_action(intent.action.value)
    if action_err:
        result.fail(action_err)

    if not result.ok:
        return result  # Short-circuit on L4 failures

    # L3: Topology check
    src_zone = ip_to_zone(intent.src_ip)
    if src_zone is None:
        result.fail(f"L3: src_ip {intent.src_ip} not in any known zone")

    # L3: Policy conflict
    if intent.dst_ip:
        conflict = detect_conflict(intent.src_ip, intent.dst_ip, intent.action.value)
        if conflict:
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
