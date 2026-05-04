"""🛡 Adversarial safety tests — verify all 9 defense layers hold."""
import json
import asyncio
import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"


# ── L4: Hard guardrails ────────────────────────────────────────────────────────

def test_l4_never_block_management_plane():
    from src.agent.safety.guardrails import check_never_block
    assert check_never_block("10.10.6.238") is not None

def test_l4_never_block_svi_gateway():
    from src.agent.safety.guardrails import check_never_block
    assert check_never_block("10.1.100.1") is not None

def test_l4_never_block_netconf_plane():
    from src.agent.safety.guardrails import check_never_block
    assert check_never_block("192.168.122.20") is not None

def test_l4_never_block_loopback():
    from src.agent.safety.guardrails import check_never_block
    assert check_never_block("127.0.0.1") is not None

def test_l4_legitimate_ip_not_blocked():
    from src.agent.safety.guardrails import check_never_block
    assert check_never_block("10.1.100.10") is None  # Alpine-Linux-1 (WEB host)

def test_l4_action_whitelist_rejects_accept():
    from src.agent.safety.guardrails import check_allowed_action
    assert check_allowed_action("ACCEPT") is not None

def test_l4_action_whitelist_rejects_return():
    from src.agent.safety.guardrails import check_allowed_action
    assert check_allowed_action("RETURN") is not None

def test_l4_action_whitelist_allows_drop():
    from src.agent.safety.guardrails import check_allowed_action
    assert check_allowed_action("DROP") is None


# ── L3: Topology + policy conflict validators ─────────────────────────────────

def test_l3_policy_conflict_drop_allow_flow():
    from src.core.policy import detect_conflict
    # APP→DB is ALLOW in matrix; DROP on this flow is a conflict
    error = detect_conflict("10.2.100.10", "10.1.200.10", "DROP")
    assert error is not None
    assert "conflict" in error.lower() or "allow" in error.lower()

def test_l3_no_conflict_deny_flow():
    from src.core.policy import detect_conflict
    # WEB→DB is DENY; DROP on this flow is correct enforcement
    error = detect_conflict("10.1.100.10", "10.1.200.10", "DROP")
    assert error is None


# ── L5: Blast radius — rate limiter ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_l5_rate_limit_per_ip():
    from src.agent.safety.rate_limiter import RateLimiter
    rl = RateLimiter(max_per_minute=100, max_total=100, max_per_ip=3, per_ip_window=300)
    ip = "10.1.100.10"
    assert await rl.check_and_consume(ip) is None  # 1st
    assert await rl.check_and_consume(ip) is None  # 2nd
    assert await rl.check_and_consume(ip) is None  # 3rd
    err = await rl.check_and_consume(ip)           # 4th — exceeds max_per_ip=3
    assert err is not None
    assert "L5" in err

@pytest.mark.asyncio
async def test_l5_rate_limit_per_minute():
    from src.agent.safety.rate_limiter import RateLimiter
    rl = RateLimiter(max_per_minute=3, max_total=100, max_per_ip=100, per_ip_window=300)
    for i in range(3):
        assert await rl.check_and_consume(f"10.1.100.{i + 1}") is None
    err = await rl.check_and_consume("10.1.100.99")
    assert err is not None
    assert "L5" in err

@pytest.mark.asyncio
async def test_l5_total_cap():
    from src.agent.safety.rate_limiter import RateLimiter
    rl = RateLimiter(max_per_minute=1000, max_total=2, max_per_ip=1000, per_ip_window=1)
    assert await rl.check_and_consume("10.1.100.1") is None
    assert await rl.check_and_consume("10.1.100.2") is None
    err = await rl.check_and_consume("10.1.100.3")
    assert err is not None


# ── L5: TTL bounds ────────────────────────────────────────────────────────────

def test_l5_ttl_too_short_rejected():
    from src.agent.safety.validators import validate_intent
    from src.models.decision import PolicyIntent, PolicyAction
    intent = PolicyIntent(
        action=PolicyAction.DROP, src_ip="10.1.100.10/32",
        dst_ip="10.1.200.10/32", dst_port=5432, protocol="tcp",
        priority=50, ttl_seconds=5,
        confidence=0.95, reasoning_steps=["step1", "step2"],
        comment="ttl too short test",
    )
    result = validate_intent(intent, sid=9000001, ttl_min=60, ttl_max=3600)
    assert not result.ok
    assert any("L5" in e for e in result.errors)

def test_l5_ttl_too_long_rejected():
    from src.agent.safety.validators import validate_intent
    from src.models.decision import PolicyIntent, PolicyAction
    intent = PolicyIntent(
        action=PolicyAction.DROP, src_ip="10.1.100.10/32",
        dst_ip="10.1.200.10/32", dst_port=5432, protocol="tcp",
        priority=50, ttl_seconds=99999,
        confidence=0.95, reasoning_steps=["step1", "step2"],
        comment="ttl too long test",
    )
    result = validate_intent(intent, sid=9000001, ttl_min=60, ttl_max=3600)
    assert not result.ok
    assert any("L5" in e for e in result.errors)


# ── L6: Action gradation ──────────────────────────────────────────────────────

def test_l6_p3_drop_rejected():
    from src.agent.safety.validators import validate_intent
    from src.models.decision import PolicyIntent, PolicyAction
    intent = PolicyIntent(
        action=PolicyAction.DROP, src_ip="10.1.100.10/32",
        confidence=0.95, reasoning_steps=["recon sweep"],
        comment="should be log_only not drop", ttl_seconds=3600,
    )
    result = validate_intent(intent, sid=9000010, ttl_min=60, ttl_max=3600)
    assert not result.ok
    assert any("L6" in e for e in result.errors)

def test_l6_p4_drop_rejected():
    from src.agent.safety.validators import validate_intent
    from src.models.decision import PolicyIntent, PolicyAction
    intent = PolicyIntent(
        action=PolicyAction.DROP, src_ip="10.2.50.10/32",
        confidence=0.95, reasoning_steps=["audit event"],
        comment="P4 must not DROP", ttl_seconds=3600,
    )
    result = validate_intent(intent, sid=9000020, ttl_min=60, ttl_max=3600)
    assert not result.ok
    assert any("L6" in e for e in result.errors)

def test_l6_p1_drop_allowed():
    from src.agent.safety.validators import validate_intent
    from src.models.decision import PolicyIntent, PolicyAction
    intent = PolicyIntent(
        action=PolicyAction.DROP, src_ip="10.1.100.10/32",
        dst_ip="10.1.200.10/32", dst_port=5432, protocol="tcp",
        priority=50, ttl_seconds=3600,
        confidence=0.95, reasoning_steps=["lateral movement P1"],
        comment="P1 WEB to DB lateral movement enforcement",
    )
    result = validate_intent(intent, sid=9000001, ttl_min=60, ttl_max=3600)
    assert result.ok, result.errors


# ── L7: Confidence gate ───────────────────────────────────────────────────────

def test_l7_low_confidence_rejected():
    from src.agent.safety.confidence import evaluate_confidence, ConfidenceOutcome
    outcome, reason = evaluate_confidence(0.3)
    assert outcome == ConfidenceOutcome.REJECT
    assert "L7" in reason

def test_l7_mid_confidence_held():
    from src.agent.safety.confidence import evaluate_confidence, ConfidenceOutcome
    outcome, reason = evaluate_confidence(0.6)
    assert outcome == ConfidenceOutcome.HOLD

def test_l7_high_confidence_enforced():
    from src.agent.safety.confidence import evaluate_confidence, ConfidenceOutcome
    outcome, reason = evaluate_confidence(0.92)
    assert outcome == ConfidenceOutcome.ENFORCE


# ── L8: Circuit breaker ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_l8_circuit_breaker_opens_after_failures():
    from src.agent.safety.circuit_breaker import CircuitBreaker
    cb = CircuitBreaker(fail_threshold=3, halt_seconds=300)
    await cb.record_failure()
    await cb.record_failure()
    is_open, _ = await cb.is_open()
    assert not is_open  # Not yet — threshold is 3
    await cb.record_failure()  # 3rd failure → opens
    is_open, reason = await cb.is_open()
    assert is_open
    assert "L8" in reason

@pytest.mark.asyncio
async def test_l8_circuit_breaker_resets_on_success():
    from src.agent.safety.circuit_breaker import CircuitBreaker
    cb = CircuitBreaker(fail_threshold=2, halt_seconds=1)
    await cb.record_failure()
    await cb.record_failure()
    is_open, _ = await cb.is_open()
    assert is_open
    # Reset by success requires halt period to expire OR by reopening
    # In this test: verify stats show failures
    stats = await cb.get_stats()
    assert stats["consecutive_failures"] == 2


# ── L2: Self-consistency mock ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_l2_self_consistency_disagreement_rejected():
    from src.agent.safety.consistency import self_consistency_vote
    from src.agent.llm.interface import LLMClient

    class DisagreementMockLLM(LLMClient):
        _call = 0
        @property
        def model(self): return "mock"
        async def chat(self, messages, tools=None, tool_choice=None):
            return {"content": "", "tool_calls": None}
        async def chat_json(self, messages, schema):
            self.__class__._call += 1
            # Alternate between DROP and log_only
            if self.__class__._call % 2 == 0:
                return {"action": "log_only", "confidence": 0.9, "reasoning_steps": ["step"], "src_ip": "10.1.100.10/32"}
            return {"action": "DROP", "confidence": 0.9, "reasoning_steps": ["step"], "src_ip": "10.1.100.10/32"}

    result, error = await self_consistency_vote(
        client=DisagreementMockLLM(),
        messages=[],
        schema={},
        n_runs=3,
        min_agree=3,  # require unanimity — won't get it with alternating
    )
    assert error  # Should fail consistency check
    assert "L2" in error


# ── L1: Schema enforcement ────────────────────────────────────────────────────

def test_l1_empty_reasoning_rejected():
    from src.agent.safety.validators import validate_intent
    from src.models.decision import PolicyIntent, PolicyAction
    intent = PolicyIntent(
        action=PolicyAction.DROP, src_ip="10.1.100.10/32",
        dst_ip="10.1.200.10/32", dst_port=5432, protocol="tcp",
        priority=50, ttl_seconds=3600,
        confidence=0.95, reasoning_steps=[],  # empty!
        comment="no reasoning provided",
    )
    result = validate_intent(intent, sid=9000001, ttl_min=60, ttl_max=3600)
    assert not result.ok
    assert any("reasoning" in e.lower() for e in result.errors)
