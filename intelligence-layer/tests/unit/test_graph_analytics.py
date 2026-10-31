"""Multi-hop graph analytics + host-scope validator guard."""
from src.agent.safety.validators import validate_intent
from src.core import graph_analytics as g
from src.models.decision import PolicyAction, PolicyIntent

APP_CORE, DB_OLTP, WEB, APP_GW = "10.2.100.10", "10.1.200.10", "10.1.100.10", "10.3.100.10"


def _scope(opts, name):
    return next(o for o in opts if o["scope"] == name)


def test_host_scope_cuts_more_legit_flows_than_flow_scope():
    opts = g.containment_options(APP_CORE, DB_OLTP, 5432)
    flow, host = _scope(opts, "flow"), _scope(opts, "host")
    assert [f["name"] for f in flow["legit_flows_cut"]] == ["appcore-to-dboltp"]
    assert host["n_cut"] > flow["n_cut"]
    assert host["crown_jewels_still_reachable"] == []


def test_denied_flow_scope_has_no_collateral():
    flow = _scope(g.containment_options(WEB, DB_OLTP, 5432), "flow")
    assert flow["n_cut"] == 0


def test_attack_surface_shortest_path_to_crown_jewel():
    surf = g.attack_surface(WEB)
    assert [h["zone"] for h in surf["next_hops"]] == ["APP-GW"]
    db = next(p for p in surf["crown_jewel_paths"] if "DB-OLTP" in p["target"])
    assert db["path"] == "WEB -> APP-GW -> APP-CORE -> DB-OLTP" and db["hops"] == 3


def test_pivot_chain_finds_upstream_root_cause():
    alerts = [
        {"src_ip": WEB, "dest_ip": APP_GW, "timestamp": "2026-10-25T05:00:00+00:00",
         "alert": {"signature_id": 9000041}},
        {"src_ip": APP_GW, "dest_ip": DB_OLTP, "timestamp": "2026-10-25T05:02:00+00:00",
         "alert": {"signature_id": 9000004}},
    ]
    piv = g.pivot_chain(APP_GW, alerts, now=g._ts(alerts[1]) + 10)
    assert piv["is_pivot"] and piv["root_cause_src"] == WEB
    assert piv["distinct_targets_from_src"] == [DB_OLTP]


def test_no_pivot_without_upstream_alert():
    piv = g.pivot_chain(WEB, [], now=0)
    assert not piv["is_pivot"] and piv["root_cause_src"] == WEB


def test_host_scope_on_permitted_path_is_rejected():
    """Empty dst_ip must not bypass the policy-conflict check (APP-GW→APP-CORE is ALLOW)."""
    intent = PolicyIntent(action=PolicyAction.DROP, src_ip=f"{APP_GW}/32", dst_ip="",
                          dst_port=0, confidence=0.95, ttl_seconds=1800)
    res = validate_intent(intent, sid=9000041, ttl_min=60, ttl_max=3600,
                          alert_src_ip=APP_GW, alert_dst_ip=APP_CORE)
    assert not res.ok and any("L3" in e for e in res.errors)


def test_host_scope_on_denied_path_is_allowed():
    intent = PolicyIntent(action=PolicyAction.DROP, src_ip=f"{WEB}/32", dst_ip="",
                          dst_port=0, confidence=0.95, ttl_seconds=3600)
    res = validate_intent(intent, sid=9000001, ttl_min=60, ttl_max=3600,
                          alert_src_ip=WEB, alert_dst_ip=DB_OLTP)
    assert res.ok, res.errors


def _flow_intent(src, dst, port, conf, ttl=3600):
    return PolicyIntent(action=PolicyAction.DROP, src_ip=f"{src}/32", dst_ip=f"{dst}/32",
                        dst_port=port, confidence=conf, ttl_seconds=ttl)


def test_semantic_override_admitted_for_flow_scope_high_confidence():
    """Unknown (ET-style) SID on a permitted path: flow scope, conf>=0.90, IDS P1."""
    intent = _flow_intent(WEB, APP_GW, 8080, 0.93)
    res = validate_intent(intent, sid=2006445, ttl_min=60, ttl_max=3600,
                          alert_src_ip=WEB, alert_dst_ip=APP_GW, alert_severity=1)
    assert res.ok and res.semantic_override
    assert intent.ttl_seconds == 1800


def test_semantic_override_refused_low_confidence_or_low_severity():
    for conf, sev in ((0.88, 1), (0.95, 3)):
        res = validate_intent(_flow_intent(WEB, APP_GW, 8080, conf), sid=2006445, ttl_min=60,
                              ttl_max=3600, alert_src_ip=WEB, alert_dst_ip=APP_GW, alert_severity=sev)
        assert not res.ok and not res.semantic_override


def test_semantic_override_never_widens_to_pair_or_host():
    pair = PolicyIntent(action=PolicyAction.DROP, src_ip=f"{WEB}/32", dst_ip=f"{APP_GW}/32",
                        dst_port=0, confidence=0.97, ttl_seconds=1800)
    res = validate_intent(pair, sid=2006445, ttl_min=60, ttl_max=3600,
                          alert_src_ip=WEB, alert_dst_ip=APP_GW, alert_severity=1)
    assert not res.ok


def test_signal_scope_mapping():
    from src.agent.nodes import _signal_scope
    base = {"pivot": "no", "distinct_targets": 1, "ports_on_this_target": 1,
            "crown_jewel_path_open_under_flow_scope": "yes"}
    assert _signal_scope(base) == "flow"
    assert _signal_scope({**base, "ports_on_this_target": 3}) == "pair"
    assert _signal_scope({**base, "pivot": "yes"}) == "host"
    assert _signal_scope({**base, "distinct_targets": 2,
                          "crown_jewel_path_open_under_flow_scope": "no"}) == "flow"


def test_never_block_includes_kb_protected_hosts():
    from src.agent.safety.guardrails import NEVER_BLOCK, is_protected_ip
    for ip in ("10.2.50.10", "10.2.50.11", "10.4.200.10", "10.4.200.11", "192.168.122.205",
               "192.168.122.20", "10.3.100.1"):
        assert is_protected_ip(ip), ip
    assert not is_protected_ip("10.1.100.10")
    assert len(NEVER_BLOCK) >= 20


def test_protected_source_drop_is_rejected():
    intent = PolicyIntent(action=PolicyAction.DROP, src_ip="10.4.200.10/32", dst_ip="8.8.8.8/32",
                          dst_port=443, confidence=0.95, ttl_seconds=3600)
    res = validate_intent(intent, sid=9000060, ttl_min=60, ttl_max=3600,
                          alert_src_ip="10.4.200.10", alert_dst_ip="8.8.8.8", alert_severity=2)
    assert not res.ok and any("NEVER_BLOCK" in e for e in res.errors)


def test_responder_to_management_initiator_is_not_blocked():
    """APP-CORE answering MGT's control connection must never be DROPped."""
    intent = PolicyIntent(action=PolicyAction.DROP, src_ip=f"{APP_CORE}/32", dst_ip="",
                          dst_port=0, confidence=0.95, ttl_seconds=3600)
    res = validate_intent(intent, sid=9000011, ttl_min=60, ttl_max=3600, alert_src_ip=APP_CORE,
                          alert_dst_ip="10.2.50.10", alert_severity=1, alert_initiator_ip="10.2.50.10")
    assert not res.ok and any("L4c" in e for e in res.errors)


def test_responder_host_scope_rejected_flow_scope_allowed():
    host = PolicyIntent(action=PolicyAction.DROP, src_ip=f"{DB_OLTP}/32", dst_ip="",
                        dst_port=0, confidence=0.95, ttl_seconds=3600)
    res = validate_intent(host, sid=9000001, ttl_min=60, ttl_max=3600, alert_src_ip=DB_OLTP,
                          alert_dst_ip=WEB, alert_severity=1, alert_initiator_ip=WEB)
    assert not res.ok and any("L4c" in e for e in res.errors)


def test_ttl_sweeper_revokes_due_rules():
    import asyncio, time
    from src.enforcement import ttl_sweeper
    from src.models.enforcement import EnforcementResult

    class FakeRedis:
        def __init__(self):
            self.z = {}
            self.client = self

        async def zadd(self, key, mapping):
            self.z.update(mapping)

        async def zrangebyscore(self, key, lo, hi):
            return [k for k, v in self.z.items() if v <= hi]

        async def zrem(self, key, member):
            self.z.pop(member, None)

    class FakeBackend:
        def __init__(self):
            self.revoked = []

        async def revoke(self, rule_id):
            self.revoked.append(rule_id)
            return EnforcementResult(success=True, rule_id=rule_id, backend="fake")

    r, b = FakeRedis(), FakeBackend()
    r.z = {"agent-old": time.time() - 5, "agent-new": time.time() + 600}
    out = asyncio.run(ttl_sweeper.sweep_once(r, b))
    assert out == ["agent-old"] and b.revoked == ["agent-old"] and "agent-new" in r.z


def test_target_fidelity_rejects_wider_cidr():
    """I2: a /8 (or /24) containing the alert source is NOT the source — reject."""
    for cidr in ("10.0.0.0/8", "10.1.100.0/24", "0.0.0.0/0"):
        intent = PolicyIntent(action=PolicyAction.DROP, src_ip=cidr, dst_ip=f"{DB_OLTP}/32",
                              dst_port=5432, confidence=0.95, ttl_seconds=3600)
        res = validate_intent(intent, sid=9000001, ttl_min=60, ttl_max=3600,
                              alert_src_ip=WEB, alert_dst_ip=DB_OLTP, alert_severity=1)
        assert not res.ok and any("L4b" in e for e in res.errors), cidr
    ok = PolicyIntent(action=PolicyAction.DROP, src_ip=f"{WEB}/32", dst_ip=f"{DB_OLTP}/32",
                      dst_port=5432, confidence=0.95, ttl_seconds=3600)
    assert validate_intent(ok, sid=9000001, ttl_min=60, ttl_max=3600, alert_src_ip=WEB,
                           alert_dst_ip=DB_OLTP, alert_severity=1).ok


def test_rule_cap_counts_active_rules_not_lifetime():
    import asyncio
    from src.agent.safety.rate_limiter import RateLimiter
    rl = RateLimiter(max_per_minute=100, max_total=2, max_per_ip=100)
    assert asyncio.run(rl.check_and_consume("10.1.100.10", active_rules=0)) is None
    assert asyncio.run(rl.check_and_consume("10.1.100.10", active_rules=1)) is None
    # lifetime count is now 2 but only 1 rule is still active → still admitted
    assert asyncio.run(rl.check_and_consume("10.1.100.10", active_rules=1)) is None
    assert "cap" in asyncio.run(rl.check_and_consume("10.1.100.10", active_rules=2))
