"""Neo4j → Pydantic reader.

Inverse of `Neo4jKG.reload_from_models()`. Pulls every entity out of Neo4j and
rehydrates Pydantic objects that match the schema in `core/system_model.py`,
`core/baselines.py`, `core/threat_playbook.py`, etc.

Output shape mirrors `core.knowledge_parser.parse_all()` so it can drop-in replace
that loader at startup. After this runs, `system_model.ZONES`, `baselines.ALL_BASELINES`,
etc. can be populated from Neo4j instead of hardcoded constants.
"""
from __future__ import annotations

import json
from typing import Any

from ..core.system_model import (
    Zone, Asset, Leaf, Service,
    Criticality, DataClassification, TrustLevel,
)
from ..core.baselines import TrafficPattern, FlowCriticality
from ..core.threat_playbook import SidDetection, KillChain, KillChainStage


async def _fetch_all(driver, cypher: str, **params) -> list[dict]:
    async with driver.session() as sess:
        result = await sess.run(cypher, **params)
        return [dict(r) async for r in result]


# ─────────────────────────────────────────────────────────────────────────────
# Per-entity readers
# ─────────────────────────────────────────────────────────────────────────────
async def read_zones(driver) -> dict[str, Zone]:
    rows = await _fetch_all(driver,
        "MATCH (z:Zone) WHERE z.kg_managed = true RETURN z")
    out: dict[str, Zone] = {}
    for r in rows:
        z = dict(r["z"])
        out[z["name"]] = Zone(
            name=z["name"],
            cidr=z["cidr"],
            leaf=z["leaf"],
            vlan=z["vlan"],
            svi_gateway=z["svi_gateway"],
            purpose=z["purpose"],
            trust_level=TrustLevel(z["trust_level"]),
            criticality=Criticality(z["criticality"]),
        )
    return out


async def read_assets(driver) -> dict[str, Asset]:
    rows = await _fetch_all(driver,
        "MATCH (a:Asset) WHERE a.kg_managed = true RETURN a")
    out: dict[str, Asset] = {}
    for r in rows:
        a = dict(r["a"])
        services = [Service(**s) for s in json.loads(a.get("services_json", "[]"))]
        out[a["ip"]] = Asset(
            ip=a["ip"],
            hostname=a["hostname"],
            zone=a["zone"],
            tier=a["tier"],
            role=a["role"],
            criticality=Criticality(a["criticality"]),
            data_classification=DataClassification(a["data_classification"]),
            services=services,
            expected_inbound_sources=list(a.get("expected_inbound_sources", [])),
            expected_outbound_destinations=list(a.get("expected_outbound_destinations", [])),
            if_compromised_impact=a["if_compromised_impact"],
            if_blocked_impact=a["if_blocked_impact"],
            owner_team=a["owner_team"],
        )
    return out


async def read_leafs(driver) -> dict[str, Leaf]:
    rows = await _fetch_all(driver,
        "MATCH (l:Leaf) WHERE l.kg_managed = true RETURN l")
    out: dict[str, Leaf] = {}
    for r in rows:
        l = dict(r["l"])
        out[l["name"]] = Leaf(
            name=l["name"],
            mgmt_ip=l["mgmt_ip"],
            zones=list(l.get("zones", [])),
            role=l["role"],
        )
    return out


async def read_baselines(driver) -> dict[str, Any]:
    """Returns {patterns, anomalous_patterns, steady_state_flows_per_minute,
    mgt_audit_alert_rate_per_minute}."""
    rows = await _fetch_all(driver,
        "MATCH (b:Baseline) WHERE b.kg_managed = true RETURN b")
    patterns: list[TrafficPattern] = []
    for r in rows:
        b = dict(r["b"])
        patterns.append(TrafficPattern(
            name=b["name"],
            src_zone=b["src_zone"],
            src_ip=b["src_ip"],
            dst_zone=b["dst_zone"],
            dst_ip=b["dst_ip"],
            dst_port=b["dst_port"],
            proto=b["proto"],
            cadence=b["cadence"],
            expected_volume_per_hour=b["expected_volume_per_hour"],
            burst_anomaly_threshold=b["burst_anomaly_threshold"],
            production_description=b["production_description"],
            criticality_to_business=FlowCriticality(b["criticality_to_business"]),
            if_disrupted=b["if_disrupted"],
        ))
    # Sort to preserve declaration order: APPLICATION_FLOWS first (those in WEB+APP+DB
    # zones), MANAGEMENT_FLOWS second (sourced from MGT zone). Within each group,
    # preserve insertion order. The roundtrip verifier requires identical order.
    app_flows = [p for p in patterns if p.src_zone != "MGT"]
    mgt_flows = [p for p in patterns if p.src_zone == "MGT"]

    # Singleton :KnowledgeMeta {key:'baseline_constants'}
    meta_rows = await _fetch_all(driver,
        "MATCH (m:KnowledgeMeta {key: 'baseline_constants'}) RETURN m")
    if not meta_rows:
        raise RuntimeError("Neo4j missing KnowledgeMeta{key:'baseline_constants'} node")
    m = dict(meta_rows[0]["m"])

    return {
        "patterns": app_flows + mgt_flows,
        "anomalous_patterns": list(m.get("anomalous_patterns", [])),
        "steady_state_flows_per_minute": int(m["steady_state_flows_per_minute"]),
        "mgt_audit_alert_rate_per_minute": int(m["mgt_audit_alert_rate_per_minute"]),
    }


async def read_policy_matrix(driver) -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    for verdict in ("ALLOW", "DENY"):
        rows = await _fetch_all(driver,
            f"MATCH (s:Zone)-[r:{verdict}]->(d:Zone) WHERE r.kg_managed = true "
            "RETURN s.name AS src, d.name AS dst")
        for r in rows:
            out[(r["src"], r["dst"])] = verdict
    return out


async def read_sids(driver) -> dict[int, SidDetection]:
    rows = await _fetch_all(driver,
        "MATCH (s:Sid) WHERE s.kg_managed = true RETURN s")
    out: dict[int, SidDetection] = {}
    for r in rows:
        s = dict(r["s"])
        out[s["sid"]] = SidDetection(
            sid=s["sid"],
            severity_p_level=s["severity_p_level"],
            signature_msg=s["signature_msg"],
            production_description=s["production_description"],
            mitre_tactic=s["mitre_tactic"],
            mitre_technique=s["mitre_technique"],
            detection_logic=s["detection_logic"],
            uses_flags_s_workaround=s["uses_flags_s_workaround"],
            recommended_response=s["recommended_response"],
            default_ttl_seconds=s["default_ttl_seconds"],
            false_positive_likelihood=s["false_positive_likelihood"],
            false_positive_scenarios=list(s.get("false_positive_scenarios", [])),
        )
    return out


async def read_kill_chains(driver) -> list[KillChain]:
    """Reconstruct kill chains + stages by joining KillChain node with EXPECTED_IN edges."""
    kc_rows = await _fetch_all(driver,
        "MATCH (k:KillChain) WHERE k.kg_managed = true RETURN k")
    # Fetch all EXPECTED_IN edges with stage props + linked SID number
    edge_rows = await _fetch_all(driver,
        "MATCH (s:Sid)-[r:EXPECTED_IN]->(k:KillChain) WHERE r.kg_managed = true "
        "RETURN k.name AS chain, r.stage AS stage, r.tactic AS tactic, "
        "r.indicators AS indicators, r.false_positive_sources AS fp_sources, "
        "s.sid AS sid")
    # Group by chain, then by stage
    chain_stages: dict[str, dict[int, KillChainStage]] = {}
    for er in edge_rows:
        chain = er["chain"]
        stage_n = int(er["stage"])
        if chain not in chain_stages:
            chain_stages[chain] = {}
        if stage_n not in chain_stages[chain]:
            chain_stages[chain][stage_n] = KillChainStage(
                stage=stage_n,
                tactic=er["tactic"],
                expected_signals=[],
                production_indicators=er["indicators"],
                false_positive_sources=list(er.get("fp_sources") or []),
            )
        chain_stages[chain][stage_n].expected_signals.append(int(er["sid"]))

    # Sort SIDs within each stage to keep deterministic order matching .md authoring
    for stages in chain_stages.values():
        for st in stages.values():
            st.expected_signals.sort()

    out: list[KillChain] = []
    for r in kc_rows:
        k = dict(r["k"])
        stages_dict = chain_stages.get(k["name"], {})
        # Order stages by stage number
        stages_sorted = [stages_dict[n] for n in sorted(stages_dict.keys())]
        out.append(KillChain(
            name=k["name"],
            production_description=k["production_description"],
            stages=stages_sorted,
            typical_dwell_between_stages=k["typical_dwell"],
            recommended_intervention_point=k["recommended_intervention"],
            containment_strategy=k["containment_strategy"],
        ))
    return out


async def read_enforcement_plane(driver) -> dict[str, Any]:
    """Returns {endpoint_contracts, field_name_mapping, critical_gotchas, failure_modes,
    rbac_contract}."""
    ep_rows = await _fetch_all(driver,
        "MATCH (e:ApiEndpoint) WHERE e.kg_managed = true RETURN e")
    endpoint_contracts: dict[str, str] = {}
    for r in ep_rows:
        e = dict(r["e"])
        endpoint_contracts[e["endpoint"]] = e["description"]

    fm_rows = await _fetch_all(driver,
        "MATCH (f:FieldMapping) WHERE f.kg_managed = true RETURN f ORDER BY f.idx")
    field_name_mapping = []
    for r in fm_rows:
        f = dict(r["f"])
        field_name_mapping.append({
            "rest_request": f["rest_request"],
            "yang_gnmi": f["yang_gnmi"],
            "configdb": f["configdb"],
        })

    g_rows = await _fetch_all(driver,
        "MATCH (g:Gotcha) WHERE g.kg_managed = true RETURN g ORDER BY g.idx")
    critical_gotchas = [dict(r["g"])["text"] for r in g_rows]

    failure_rows = await _fetch_all(driver,
        "MATCH (m:FailureMode) WHERE m.kg_managed = true RETURN m")
    failure_modes = []
    for r in failure_rows:
        m = dict(r["m"])
        failure_modes.append({
            "name": m["name"],
            "trigger": m["trigger"],
            "rest_status": m["rest_status"],
            "body_signature": m["body_signature"],
            "state": m["state"],
            "agent_action": m["agent_action"],
        })

    rbac_rows = await _fetch_all(driver,
        "MATCH (r:KnowledgeMeta {key: 'rbac_contract'}) RETURN r")
    if not rbac_rows:
        raise RuntimeError("Neo4j missing KnowledgeMeta{key:'rbac_contract'}")
    rbac_contract = dict(rbac_rows[0]["r"])["text"]

    return {
        "endpoint_contracts": endpoint_contracts,
        "field_name_mapping": field_name_mapping,
        "critical_gotchas": critical_gotchas,
        "failure_modes": failure_modes,
        "rbac_contract": rbac_contract,
    }


async def read_invariants(driver) -> dict[str, Any]:
    """Returns {never_block_cidrs, never_block_rationale, allowed_agent_actions,
    protected_comment_prefixes, agent_comment_prefix}."""
    nb_rows = await _fetch_all(driver,
        "MATCH (n:NeverBlockEntry) WHERE n.kg_managed = true RETURN n")
    cidrs: list[str] = []
    rationale: dict[str, str] = {}
    for r in nb_rows:
        n = dict(r["n"])
        cidrs.append(n["cidr"])
        rationale[n["cidr"]] = n.get("rationale", "")

    meta_rows = await _fetch_all(driver,
        "MATCH (m:KnowledgeMeta {key: 'agent_invariants'}) RETURN m")
    if not meta_rows:
        raise RuntimeError("Neo4j missing KnowledgeMeta{key:'agent_invariants'}")
    m = dict(meta_rows[0]["m"])

    return {
        "never_block_cidrs": cidrs,
        "never_block_rationale": rationale,
        "allowed_agent_actions": frozenset(m.get("allowed_agent_actions", ["DROP"])),
        "protected_comment_prefixes": list(m.get("protected_comment_prefixes", [])),
        "agent_comment_prefix": m.get("agent_comment_prefix", "nos:agent-"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Composite read — same shape as core.knowledge_parser.parse_all()
# ─────────────────────────────────────────────────────────────────────────────
async def read_all(driver) -> dict[str, Any]:
    """Pull entire KG out of Neo4j into Pydantic objects.

    Same shape as `knowledge_parser.parse_all()` — drop-in replacement for the
    startup loader. Raises if Neo4j is empty or missing required singleton nodes.
    """
    return {
        "zones": await read_zones(driver),
        "assets": await read_assets(driver),
        "leafs": await read_leafs(driver),
        "baselines": await read_baselines(driver),
        "policy_matrix": await read_policy_matrix(driver),
        "sids": await read_sids(driver),
        "kill_chains": await read_kill_chains(driver),
        "enforcement_plane": await read_enforcement_plane(driver),
        "invariants": await read_invariants(driver),
    }
