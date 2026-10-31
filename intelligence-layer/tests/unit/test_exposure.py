"""Exposure metrics and mechanical SID coverage over the policy matrix."""
from src.core import exposure as ex
from src.core import sid_coverage as sc

WEB, APP_CORE, DB_OLTP = "10.1.100.10", "10.2.100.10", "10.1.200.10"


def test_segmentation_reduces_attack_surface():
    flat = ex.exposure_metrics(ex.flat_edges())
    static = ex.exposure_metrics(ex.service_edges())
    assert flat["ENICE"] == 56 and static["ENICE"] == 28          # 8 zones, 56 ordered pairs
    assert static["CJR"] < flat["CJR"]
    assert static["MPL"] > flat["MPL"]                            # more hops to a crown jewel


def test_crown_jewels_are_the_critical_confidential_zones():
    assert ex.crown_jewel_zones() == {"DB-OLTP", "DB-ANALYTICS", "MGT"}


def test_host_scope_fully_contains_source_and_cuts_most():
    host = ex.containment_effect(APP_CORE, "", 0)
    flow = ex.containment_effect(APP_CORE, DB_OLTP, 5432)
    assert host["scope"] == "host" and flow["scope"] == "flow"
    assert host["zones_reachable_after"] == 0 and host["crown_jewel_contained"]
    assert host["legit_flows_cut"] > flow["legit_flows_cut"]


def test_flow_scope_closes_the_observed_service_but_not_the_zone():
    e = ex.containment_effect(APP_CORE, DB_OLTP, 5432)
    assert e["observed_path_blocked"]
    assert e["service_reduction"] == 1                            # one service edge closed
    assert e["zones_reachable_after"] == e["zones_reachable_before"]   # zone still reachable


def test_denied_cell_containment_adds_no_exposure_reduction():
    """WEB->DB-OLTP is DENY: the static matrix already blocks it, so a flow-scope rule
    there reduces neither zone nor service exposure. Runtime value must come from
    permitted-path abuse or from isolating a spreading source."""
    e = ex.containment_effect(WEB, DB_OLTP, 5432)
    assert e["service_reduction"] == 0 and e["exposure_reduction"] == 0
    assert ex.containment_effect(WEB, "", 0)["crown_jewel_contained"]


def test_scope_of_rule_tuple():
    assert ex.scope_of(f"{WEB}/32", f"{DB_OLTP}/32", 5432) == "flow"
    assert ex.scope_of(f"{WEB}/32", f"{DB_OLTP}/32", 0) == "pair"
    assert ex.scope_of(f"{WEB}/32", "", 0) == "host"


def test_sid_coverage_is_derived_and_finds_the_one_gap():
    cov = sc.coverage()
    assert cov["n_pairs"] == 56 and cov["n_deny"] == 36 and cov["n_allow"] == 20
    assert cov["deny_uncovered"] == [("MONITORING", "MGT")]       # only uncovered denied cell
    assert cov["allow_covered"] == 0                              # no zone-pair SID on ALLOW cells
    assert sc.best_sid_for("WEB", "DB-OLTP") == 9000001           # most specific wins over 9000012


def test_source_scoped_rule_may_restrict_access_to_a_protected_asset():
    """I3 forbids isolating a protected asset, not restricting access to it: blocking
    WEB -> MGT:22 contains unauthorised management access without cutting MGT off."""
    from src.agent.safety.guardrails import check_never_block
    from src.agent.safety.validators import validate_intent
    from src.models.decision import PolicyAction, PolicyIntent

    assert check_never_block(f"{WEB}/32", "10.2.50.10/32", source_scoped=True) is None
    assert check_never_block("10.2.50.10/32", f"{WEB}/32") is not None          # protected source
    assert check_never_block(f"{WEB}/32", "10.2.50.10/32", source_scoped=False) is not None

    intent = PolicyIntent(action=PolicyAction.DROP, src_ip=f"{WEB}/32",
                          dst_ip="10.2.50.10/32", dst_port=22, confidence=0.95,
                          ttl_seconds=3600)
    res = validate_intent(intent, sid=9000003, ttl_min=60, ttl_max=3600,
                          alert_src_ip=WEB, alert_dst_ip="10.2.50.10", alert_severity=1)
    assert res.ok, res.errors
