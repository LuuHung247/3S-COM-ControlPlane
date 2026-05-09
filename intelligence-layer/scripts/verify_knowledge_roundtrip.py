"""Verify knowledge_parser output matches original Pydantic constants byte-for-byte.

This is the safety check: parse knowledge/infra/*.md → Pydantic → compare to the
hardcoded constants in core/*.py. Any divergence means the .md authoring layer
diverged from code (or the dumper missed a field). Either way, do NOT delete the
constants until this script exits 0.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from src.core import system_model, baselines, threat_playbook, policy
from src.core import enforcement_plane, invariants
from src.core import knowledge_parser as kp


def _diff(label: str, expected, actual) -> int:
    """Return 0 if equal else 1 + print diff."""
    if expected == actual:
        print(f"  ✓ {label}")
        return 0
    print(f"  ✗ {label}")
    if isinstance(expected, dict) and isinstance(actual, dict):
        only_e = set(expected) - set(actual)
        only_a = set(actual) - set(expected)
        if only_e:
            print(f"      missing keys (in original, not in parsed): {sorted(only_e)}")
        if only_a:
            print(f"      extra keys   (in parsed, not in original): {sorted(only_a)}")
        for k in set(expected) & set(actual):
            if expected[k] != actual[k]:
                print(f"      key '{k}' differs:")
                print(f"        expected: {expected[k]!r}")
                print(f"        actual:   {actual[k]!r}")
                break
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            print(f"      length differs: {len(expected)} vs {len(actual)}")
        else:
            for i, (e, a) in enumerate(zip(expected, actual)):
                if e != a:
                    print(f"      index {i} differs:")
                    print(f"        expected: {e!r}")
                    print(f"        actual:   {a!r}")
                    break
    else:
        print(f"      expected: {expected!r}")
        print(f"      actual:   {actual!r}")
    return 1


def main() -> int:
    fails = 0

    print("Parsing knowledge/infra/*.md ...")
    parsed = kp.parse_all()

    print("\nComparing against original Pydantic constants:")
    fails += _diff("ZONES", system_model.ZONES, parsed["zones"])
    fails += _diff("ASSETS", system_model.ASSETS, parsed["assets"])
    fails += _diff("LEAFS", system_model.LEAFS, parsed["leafs"])

    bs = parsed["baselines"]
    fails += _diff("ALL_BASELINES (as list)", baselines.ALL_BASELINES, bs["patterns"])
    fails += _diff("ANOMALOUS_PATTERNS", baselines.ANOMALOUS_PATTERNS, bs["anomalous_patterns"])
    fails += _diff(
        "STEADY_STATE_FLOWS_PER_MINUTE",
        baselines.STEADY_STATE_FLOWS_PER_MINUTE, bs["steady_state_flows_per_minute"]
    )
    fails += _diff(
        "MGT_AUDIT_ALERT_RATE_PER_MINUTE",
        baselines.MGT_AUDIT_ALERT_RATE_PER_MINUTE, bs["mgt_audit_alert_rate_per_minute"]
    )

    fails += _diff("POLICY_MATRIX", policy.POLICY_MATRIX, parsed["policy_matrix"])
    fails += _diff("SID_DETECTIONS", threat_playbook.SID_DETECTIONS, parsed["sids"])
    fails += _diff("KILL_CHAINS", threat_playbook.KILL_CHAINS, parsed["kill_chains"])

    ep = parsed["enforcement_plane"]
    fails += _diff("ENDPOINT_CONTRACTS", enforcement_plane.ENDPOINT_CONTRACTS, ep["endpoint_contracts"])
    fails += _diff("FIELD_NAME_MAPPING", enforcement_plane.FIELD_NAME_MAPPING, ep["field_name_mapping"])
    fails += _diff("CRITICAL_GOTCHAS", enforcement_plane.CRITICAL_GOTCHAS, ep["critical_gotchas"])
    # FAILURE_MODES — compare as list-of-dicts (parser doesn't reconstruct FailureMode objects yet)
    fm_orig = [fm.model_dump() for fm in enforcement_plane.FAILURE_MODES]
    fails += _diff("FAILURE_MODES (as dicts)", fm_orig, ep["failure_modes"])
    fails += _diff(
        "RBAC_CONTRACT (stripped)",
        enforcement_plane.RBAC_CONTRACT.strip(), ep["rbac_contract"]
    )

    inv = parsed["invariants"]
    fails += _diff("NEVER_BLOCK_CIDRS", invariants.NEVER_BLOCK_CIDRS, inv["never_block_cidrs"])
    fails += _diff("NEVER_BLOCK_RATIONALE", invariants.NEVER_BLOCK_RATIONALE, inv["never_block_rationale"])
    fails += _diff("ALLOWED_AGENT_ACTIONS", invariants.ALLOWED_AGENT_ACTIONS, inv["allowed_agent_actions"])
    fails += _diff(
        "PROTECTED_COMMENT_PREFIXES",
        invariants.PROTECTED_COMMENT_PREFIXES, inv["protected_comment_prefixes"]
    )
    fails += _diff("AGENT_COMMENT_PREFIX", invariants.AGENT_COMMENT_PREFIX, inv["agent_comment_prefix"])

    print()
    if fails == 0:
        print("✓ ROUNDTRIP OK — all parsed values match original Pydantic constants exactly.")
        return 0
    print(f"✗ ROUNDTRIP FAILED — {fails} divergences. Do NOT delete constants.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
