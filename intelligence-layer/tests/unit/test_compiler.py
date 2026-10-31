"""Compiled response programs: language, exhaustive verifier, ensemble, runtime fast path."""
import asyncio
import json

import pytest

from src.compiler.dsl import Ensemble, Features, Program, ProgramError
from src.compiler.fast_path import CompiledPolicy
from src.compiler.kb import KBSnapshot
from src.compiler.verifier import realizable, verify
from src.models.alert import SuricataAlert

KB = KBSnapshot.load("knowledge_v2")
WEB, DB_OLTP, MGT1 = "10.1.100.10", "10.1.200.10", "10.2.50.10"

SAFE = {"rules": [
    {"id": "P", "when": {"src_protected": True}, "then": {"action": "log_only"}, "rationale": "protected"},
    {"id": "X", "when": {"src_zones": ["EXTERNAL"]}, "then": {"action": "log_only"}, "rationale": "external"},
    {"id": "U", "when": {"sid_known": False}, "then": {"action": "abstain"}, "rationale": "unknown"},
    {"id": "I", "when": {"severity_min": 3}, "then": {"action": "log_only"}, "rationale": "informational"},
    {"id": "D", "when": {"sids": [9000001], "verdicts": ["DENY"]},
     "then": {"action": "DROP", "scope": "flow", "ttl_seconds": 1800, "confidence": 0.95},
     "rationale": "WEB to DB bypass", "kb_refs": ["SID 9000001"]},
]}


def _prog(d=SAFE):
    return Program.from_json(json.loads(json.dumps(d)), KB.zone_names())


def _alert(sid, sev, src, dst, port, ts="2026-10-27T10:00:00+00:00"):
    return SuricataAlert.from_raw({"timestamp": ts, "event_type": "alert", "src_ip": src,
                                   "dest_ip": dst, "src_port": 40000, "dest_port": port,
                                   "proto": "TCP", "alert": {"signature_id": sid, "severity": sev,
                                                             "signature": "t", "category": "t"}})


def test_snapshot_reads_the_deployed_fabric():
    assert len(KB.zones) == 8 and len(KB.sids) == 29
    assert KB.verdict("WEB", "DB-OLTP") == "DENY" and KB.verdict("APP-CORE", "DB-OLTP") == "ALLOW"
    assert KB.is_protected(MGT1) and not KB.is_protected(WEB)
    assert KB.sid_pairs(9000001) == {("WEB", "DB-OLTP"), ("WEB", "DB-ANALYTICS")}


def test_safe_program_verifies_on_every_input():
    rep = verify(KB, _prog())
    assert rep.ok and rep.n_points == 136080
    assert rep.n_realizable < rep.n_points


def test_verifier_finds_a_drop_on_a_protected_source():
    bad = dict(SAFE, rules=SAFE["rules"][1:])           # drop the protective first rule
    rep = verify(KB, _prog(bad))
    assert not rep.ok
    assert any("I3" in msg for _, msg in rep.violations)


def test_verifier_rejects_unbounded_override_of_a_permitted_path():
    prog = dict(SAFE, rules=SAFE["rules"][:4] + [
        {"id": "A", "when": {"verdicts": ["ALLOW"], "sids": [9000072]},
         "then": {"action": "DROP", "scope": "host", "ttl_seconds": 3600, "confidence": 0.95},
         "rationale": "destructive SQL", "kb_refs": ["SID 9000072"]}])
    msgs = {m for _, m in verify(KB, _prog(prog)).violations}
    assert any(m.startswith("I4: DROP on a permitted path") for m in msgs)


def test_unknown_signature_never_auto_enforces():
    prog = dict(SAFE, rules=SAFE["rules"][:2] + [
        {"id": "Z", "when": {"verdicts": ["DENY"], "severity_max": 2},
         "then": {"action": "DROP", "scope": "flow", "ttl_seconds": 600, "confidence": 0.9},
         "rationale": "deny", "kb_refs": ["policy-matrix"]}])
    assert any(m.startswith("G1") for _, m in verify(KB, _prog(prog)).violations)


def test_language_rejects_unknown_conditions_and_zones():
    with pytest.raises(ProgramError):
        Program.from_json({"rules": [{"id": "a", "when": {"dst_ip": "x"}, "then": {"action": "DROP"},
                                      "rationale": ""}]}, KB.zone_names())
    with pytest.raises(ProgramError):
        Program.from_json({"rules": [{"id": "a", "when": {"src_zones": ["DMZ"]},
                                      "then": {"action": "log_only"}, "rationale": ""}]}, KB.zone_names())


def test_ensemble_acts_only_on_a_strict_majority_and_keeps_the_narrowest_rule():
    wide = json.loads(json.dumps(SAFE))
    wide["rules"][4]["then"].update(scope="pair", ttl_seconds=3000)
    silent = json.loads(json.dumps(SAFE))
    silent["rules"] = silent["rules"][:4]
    f = Features(9000001, 1, "WEB", "DB-OLTP", "DENY", False, 0)
    two_of_three = Ensemble([_prog(), _prog(wide), _prog(silent)]).evaluate(f)
    assert two_of_three.action == "DROP" and two_of_three.scope == "flow" and two_of_three.ttl_seconds == 1800
    assert Ensemble([_prog(), _prog(silent)]).evaluate(f).action == "abstain"     # 1 of 2: no majority
    assert verify(KB, Ensemble([_prog(), _prog(wide), _prog(silent)])).ok


def test_realizability_follows_the_catalogue():
    assert realizable(KB, Features(9000001, 1, "WEB", "DB-OLTP", "DENY", False, 0))
    assert not realizable(KB, Features(9000001, 1, "WORKER", "MGT", "DENY", False, 0))
    assert not realizable(KB, Features(9000001, 3, "WEB", "DB-OLTP", "DENY", False, 0))


def _artifact(tmp_path, digest=None, verified=True):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"verified": verified, "kb_digest": digest or KB.digest,
                             "program": SAFE, "model": "test"}))
    return str(p)


def test_fast_path_decides_and_builds_a_source_scoped_flow_rule(tmp_path):
    cp = CompiledPolicy()
    asyncio.run(cp.load(_artifact(tmp_path), "knowledge_v2"))
    assert cp.active, cp.status
    alert = _alert(9000001, 1, WEB, DB_OLTP, 5432)
    out, f = cp.decide(alert, [])
    assert out.action == "DROP" and f.verdict == "DENY" and f.prior_alerts == 0
    intent = cp.intent_for(alert, out, f)
    assert intent.src_ip == f"{WEB}/32" and intent.dst_ip == f"{DB_OLTP}/32" and intent.dst_port == 5432
    assert intent.ttl_seconds == 1800 and intent.rule_id
    assert cp.decide(_alert(9000999, 2, WEB, DB_OLTP, 5432), [])[0].action == "abstain"


def test_fast_path_history_features_use_the_window(tmp_path):
    cp = CompiledPolicy()
    asyncio.run(cp.load(_artifact(tmp_path), "knowledge_v2"))
    hist = [{"timestamp": "2026-10-27T09:58:00+00:00", "dest_ip": "10.2.100.10", "dest_port": 22},
            {"timestamp": "2026-10-27T09:59:00+00:00", "dest_ip": DB_OLTP, "dest_port": 3306},
            {"timestamp": "2026-10-27T08:00:00+00:00", "dest_ip": "10.4.100.10", "dest_port": 22}]
    f = cp.features(_alert(9000001, 1, WEB, DB_OLTP, 5432), hist)
    assert (f.prior_alerts, f.distinct_targets, f.ports_on_target) == (1, 1, 1)


def test_stale_or_unverified_artefact_is_never_activated(tmp_path):
    cp = CompiledPolicy()
    asyncio.run(cp.load(_artifact(tmp_path, digest="0" * 16), "knowledge_v2"))
    assert not cp.active and "compiled for KB" in cp.status
    asyncio.run(cp.load(_artifact(tmp_path, verified=False), "knowledge_v2"))
    assert not cp.active


def test_out_of_range_severity_maps_to_the_least_severe_level(tmp_path):
    cp = CompiledPolicy()
    asyncio.run(cp.load(_artifact(tmp_path), "knowledge_v2"))
    for sev in (0, 5, 9):
        f = cp.features(_alert(9000001, sev, WEB, DB_OLTP, 5432), [])
        assert f.severity == 4 and cp.decide(_alert(9000001, sev, WEB, DB_OLTP, 5432), [])[0].action != "DROP"
