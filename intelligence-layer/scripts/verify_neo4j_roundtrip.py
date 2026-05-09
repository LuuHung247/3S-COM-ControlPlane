"""End-to-end roundtrip test: knowledge/infra/*.md → Neo4j → Pydantic.

Compares the result of `neo4j_reader.read_all()` against `knowledge_parser.parse_all()`.
If they match, Neo4j faithfully holds the same data that .md → parser would produce
— meaning Neo4j can serve as the single runtime source of truth.

Requires Neo4j running on the URI configured by NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD
env vars (defaults: bolt://localhost:7687, neo4j, zerotrust2026).
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from src.storage.neo4j_kg import Neo4jKG
from src.storage import neo4j_reader
from src.core import knowledge_parser


def _diff(label: str, expected, actual) -> int:
    if expected == actual:
        print(f"  ✓ {label}")
        return 0
    print(f"  ✗ {label}")
    if isinstance(expected, dict) and isinstance(actual, dict):
        only_e = set(expected) - set(actual)
        only_a = set(actual) - set(expected)
        if only_e:
            print(f"      missing keys: {sorted(only_e)}")
        if only_a:
            print(f"      extra keys:   {sorted(only_a)}")
        for k in set(expected) & set(actual):
            if expected[k] != actual[k]:
                print(f"      key '{k}' differs")
                print(f"        expected: {expected[k]!r}"[:300])
                print(f"        actual:   {actual[k]!r}"[:300])
                break
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            print(f"      length differs: {len(expected)} vs {len(actual)}")
        for i, (e, a) in enumerate(zip(expected, actual)):
            if e != a:
                print(f"      index {i} differs")
                print(f"        expected: {e!r}"[:300])
                print(f"        actual:   {a!r}"[:300])
                break
    else:
        print(f"      expected: {expected!r}"[:300])
        print(f"      actual:   {actual!r}"[:300])
    return 1


async def run() -> int:
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "zerotrust2026")

    print(f"Connecting Neo4j {uri} ...")
    kg = Neo4jKG(uri, user, password)
    await kg.connect()

    print("ETL: knowledge/infra/*.md → Neo4j ...")
    counts = await kg.reload_from_models()
    print(f"  pushed {counts['nodes']} nodes, {counts['edges']} edges")

    print("\nReading back via neo4j_reader.read_all() ...")
    from_neo4j = await neo4j_reader.read_all(kg.driver)

    print("Parsing .md directly (reference) ...")
    from_md = knowledge_parser.parse_all()

    print("\nComparing Neo4j-read vs MD-parsed:")
    fails = 0
    fails += _diff("zones", from_md["zones"], from_neo4j["zones"])
    fails += _diff("assets", from_md["assets"], from_neo4j["assets"])
    fails += _diff("leafs", from_md["leafs"], from_neo4j["leafs"])
    fails += _diff("baselines.patterns", from_md["baselines"]["patterns"],
                   from_neo4j["baselines"]["patterns"])
    fails += _diff("baselines.anomalous_patterns",
                   from_md["baselines"]["anomalous_patterns"],
                   from_neo4j["baselines"]["anomalous_patterns"])
    fails += _diff("baselines.steady_state_flows_per_minute",
                   from_md["baselines"]["steady_state_flows_per_minute"],
                   from_neo4j["baselines"]["steady_state_flows_per_minute"])
    fails += _diff("baselines.mgt_audit_alert_rate_per_minute",
                   from_md["baselines"]["mgt_audit_alert_rate_per_minute"],
                   from_neo4j["baselines"]["mgt_audit_alert_rate_per_minute"])
    fails += _diff("policy_matrix", from_md["policy_matrix"], from_neo4j["policy_matrix"])
    fails += _diff("sids", from_md["sids"], from_neo4j["sids"])
    fails += _diff("kill_chains", from_md["kill_chains"], from_neo4j["kill_chains"])
    ep_md, ep_n4 = from_md["enforcement_plane"], from_neo4j["enforcement_plane"]
    fails += _diff("ep.endpoint_contracts", ep_md["endpoint_contracts"], ep_n4["endpoint_contracts"])
    fails += _diff("ep.field_name_mapping", ep_md["field_name_mapping"], ep_n4["field_name_mapping"])
    fails += _diff("ep.critical_gotchas", ep_md["critical_gotchas"], ep_n4["critical_gotchas"])
    fails += _diff("ep.failure_modes", ep_md["failure_modes"], ep_n4["failure_modes"])
    fails += _diff("ep.rbac_contract", ep_md["rbac_contract"], ep_n4["rbac_contract"])
    inv_md, inv_n4 = from_md["invariants"], from_neo4j["invariants"]
    fails += _diff("inv.never_block_cidrs", inv_md["never_block_cidrs"], inv_n4["never_block_cidrs"])
    fails += _diff("inv.never_block_rationale", inv_md["never_block_rationale"], inv_n4["never_block_rationale"])
    fails += _diff("inv.allowed_agent_actions", inv_md["allowed_agent_actions"], inv_n4["allowed_agent_actions"])
    fails += _diff("inv.protected_comment_prefixes", inv_md["protected_comment_prefixes"],
                   inv_n4["protected_comment_prefixes"])
    fails += _diff("inv.agent_comment_prefix", inv_md["agent_comment_prefix"], inv_n4["agent_comment_prefix"])

    await kg.close()

    print()
    if fails == 0:
        print("✓ NEO4J ROUNDTRIP OK — Neo4j faithfully stores .md content.")
        return 0
    print(f"✗ NEO4J ROUNDTRIP FAILED — {fails} divergences.")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
