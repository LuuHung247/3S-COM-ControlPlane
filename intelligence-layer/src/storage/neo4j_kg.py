"""Neo4j Knowledge Graph store.

Replaces in-memory NetworkX KG with persistent Neo4j storage. Pydantic models
in `core/` remain the single source of truth — this module ETLs them into
Neo4j at startup so endpoints (`/kg/visualize`, `/kg/stats`, `/kg/json`,
`/kg/export/graphml`) and future GraphRAG retrieval can query via Cypher.

Design:
  - Idempotent ETL: every startup wipes the `kg` database label set and reloads
    from Pydantic — single source of truth stays in code, no migration drift.
  - Async neo4j driver — fits FastAPI lifespan.
  - Schema: 6 node labels (Zone, Asset, Leaf, Sid, KillChain, Baseline) + edges
    (MEMBER_OF, ENFORCES, ALLOW, DENY, PART_OF, EXPECTED_IN, MITRE_TECHNIQUE).
"""
from __future__ import annotations

from typing import Any

import structlog
from neo4j import AsyncGraphDatabase

log = structlog.get_logger()


class Neo4jKG:
    """Async Neo4j KG client + ETL from Pydantic source-of-truth models."""

    def __init__(self, uri: str, user: str, password: str) -> None:
        self._uri = uri
        self._user = user
        self._password = password
        self._driver = None

    async def connect(self) -> None:
        self._driver = AsyncGraphDatabase.driver(
            self._uri, auth=(self._user, self._password)
        )
        # Verify connectivity (raises if Neo4j unreachable / auth wrong)
        await self._driver.verify_connectivity()
        log.info("neo4j_kg_connected", uri=self._uri)

    async def close(self) -> None:
        if self._driver is not None:
            await self._driver.close()

    @property
    def driver(self):
        if self._driver is None:
            raise RuntimeError("Neo4jKG not connected — call connect() first")
        return self._driver

    # ── ETL: knowledge/infra/*.md → Neo4j ────────────────────────────────────
    async def reload_from_models(self) -> dict[str, int]:
        """Idempotent reload: WIPE + RECREATE from `knowledge/infra/*.md`.

        The .md files (parsed via `core/knowledge_parser.py`) are the authoring source
        of truth. Pydantic schema validates each entity before it lands in Neo4j.
        Called at container startup. Returns counts of nodes/edges created.
        """
        import json

        from ..core import knowledge_parser as kp

        kb = kp.parse_all()
        zones = kb["zones"]
        assets = kb["assets"]
        leafs = kb["leafs"]
        baselines_data = kb["baselines"]
        patterns = baselines_data["patterns"]
        policy_matrix = kb["policy_matrix"]
        sids = kb["sids"]
        kill_chains = kb["kill_chains"]
        ep = kb["enforcement_plane"]
        inv = kb["invariants"]

        async with self._driver.session() as sess:
            # WIPE everything we own (labelled to avoid clobbering user data)
            await sess.run("MATCH (n) WHERE n.kg_managed = true DETACH DELETE n")

            counts = {"nodes": 0, "edges": 0}

            # ── Zones ────────────────────────────────────────────────────────
            for zone_name, zone in zones.items():
                await sess.run(
                    """
                    MERGE (z:Zone {name: $name})
                    SET z.kg_managed = true,
                        z.cidr = $cidr,
                        z.leaf = $leaf,
                        z.vlan = $vlan,
                        z.svi_gateway = $svi,
                        z.trust_level = $trust,
                        z.criticality = $crit,
                        z.purpose = $purpose
                    """,
                    name=zone_name,
                    cidr=zone.cidr,
                    leaf=zone.leaf,
                    vlan=zone.vlan,
                    svi=zone.svi_gateway,
                    trust=zone.trust_level.value,
                    crit=zone.criticality.value,
                    purpose=zone.purpose,
                )
                counts["nodes"] += 1

            # ── Leafs (with ENFORCES edges) ──────────────────────────────────
            for leaf_name, leaf in leafs.items():
                await sess.run(
                    """
                    MERGE (l:Leaf {name: $name})
                    SET l.kg_managed = true,
                        l.mgmt_ip = $mgmt,
                        l.role = $role,
                        l.zones = $zones
                    """,
                    name=leaf_name,
                    mgmt=leaf.mgmt_ip,
                    role=leaf.role,
                    zones=leaf.zones,
                )
                counts["nodes"] += 1
                for zone_in_leaf in leaf.zones:
                    await sess.run(
                        """
                        MATCH (l:Leaf {name: $leaf}), (z:Zone {name: $zone})
                        MERGE (l)-[r:ENFORCES]->(z)
                        SET r.kg_managed = true
                        """,
                        leaf=leaf_name,
                        zone=zone_in_leaf,
                    )
                    counts["edges"] += 1

            # ── Assets (with MEMBER_OF edges) ────────────────────────────────
            for ip, asset in assets.items():
                # services is list of nested Service objects → store as JSON string
                services_json = json.dumps([s.model_dump() for s in asset.services])
                await sess.run(
                    """
                    MERGE (a:Asset {ip: $ip})
                    SET a.kg_managed = true,
                        a.hostname = $hostname,
                        a.tier = $tier,
                        a.criticality = $crit,
                        a.data_classification = $dc,
                        a.role = $role,
                        a.owner_team = $owner,
                        a.if_blocked_impact = $impact_blocked,
                        a.if_compromised_impact = $impact_compromised,
                        a.expected_inbound_sources = $inbound,
                        a.expected_outbound_destinations = $outbound,
                        a.services_json = $services,
                        a.zone = $zone
                    """,
                    ip=ip,
                    hostname=asset.hostname,
                    tier=asset.tier,
                    crit=asset.criticality.value,
                    dc=asset.data_classification.value,
                    role=asset.role,
                    owner=asset.owner_team,
                    impact_blocked=asset.if_blocked_impact,
                    impact_compromised=asset.if_compromised_impact,
                    inbound=list(asset.expected_inbound_sources),
                    outbound=list(asset.expected_outbound_destinations),
                    services=services_json,
                    zone=asset.zone,
                )
                counts["nodes"] += 1
                await sess.run(
                    """
                    MATCH (a:Asset {ip: $ip}), (z:Zone {name: $zone})
                    MERGE (a)-[r:MEMBER_OF]->(z)
                    SET r.kg_managed = true
                    """,
                    ip=ip,
                    zone=asset.zone,
                )
                counts["edges"] += 1

            # ── Policy matrix (Zone → Zone ALLOW/DENY edges) ─────────────────
            for (src_zone, dst_zone), verdict in policy_matrix.items():
                rel = "ALLOW" if verdict == "ALLOW" else "DENY"
                await sess.run(
                    f"""
                    MATCH (s:Zone {{name: $src}}), (d:Zone {{name: $dst}})
                    MERGE (s)-[r:{rel}]->(d)
                    SET r.kg_managed = true
                    """,
                    src=src_zone,
                    dst=dst_zone,
                )
                counts["edges"] += 1

            # ── SIDs (Suricata signatures) ───────────────────────────────────
            for sid, det in sids.items():
                await sess.run(
                    """
                    MERGE (s:Sid {sid: $sid})
                    SET s.kg_managed = true,
                        s.severity_p_level = $sev,
                        s.signature_msg = $msg,
                        s.production_description = $desc,
                        s.mitre_tactic = $tactic,
                        s.mitre_technique = $technique,
                        s.detection_logic = $logic,
                        s.uses_flags_s_workaround = $flags_s,
                        s.recommended_response = $resp,
                        s.default_ttl_seconds = $ttl,
                        s.false_positive_likelihood = $fp,
                        s.false_positive_scenarios = $fp_scenarios
                    """,
                    sid=sid,
                    sev=det.severity_p_level,
                    msg=det.signature_msg,
                    desc=det.production_description,
                    tactic=det.mitre_tactic,
                    technique=det.mitre_technique,
                    logic=det.detection_logic,
                    flags_s=det.uses_flags_s_workaround,
                    resp=det.recommended_response,
                    ttl=det.default_ttl_seconds,
                    fp=det.false_positive_likelihood,
                    fp_scenarios=list(det.false_positive_scenarios),
                )
                counts["nodes"] += 1

            # ── KillChains + EXPECTED_IN edges (with full stage props) ────────
            for kc in kill_chains:
                await sess.run(
                    """
                    MERGE (k:KillChain {name: $name})
                    SET k.kg_managed = true,
                        k.production_description = $desc,
                        k.typical_dwell = $dwell,
                        k.recommended_intervention = $intervention,
                        k.containment_strategy = $strategy,
                        k.stage_count = $n
                    """,
                    name=kc.name,
                    desc=kc.production_description,
                    dwell=kc.typical_dwell_between_stages,
                    intervention=kc.recommended_intervention_point,
                    strategy=kc.containment_strategy,
                    n=len(kc.stages),
                )
                counts["nodes"] += 1
                # Each stage's expected SIDs → EXPECTED_IN edge to KillChain
                for stage in kc.stages:
                    for sid in stage.expected_signals:
                        await sess.run(
                            """
                            MATCH (s:Sid {sid: $sid}), (k:KillChain {name: $kc})
                            MERGE (s)-[r:EXPECTED_IN {stage: $stage}]->(k)
                            SET r.kg_managed = true,
                                r.tactic = $tactic,
                                r.indicators = $ind,
                                r.false_positive_sources = $fp_sources
                            """,
                            sid=sid,
                            kc=kc.name,
                            stage=stage.stage,
                            tactic=stage.tactic,
                            ind=stage.production_indicators,
                            fp_sources=list(stage.false_positive_sources),
                        )
                        counts["edges"] += 1

            # ── Baselines (legitimate flows) ─────────────────────────────────
            for b in patterns:
                await sess.run(
                    """
                    MERGE (b:Baseline {name: $name})
                    SET b.kg_managed = true,
                        b.src_zone = $src_zone,
                        b.src_ip = $src,
                        b.dst_zone = $dst_zone,
                        b.dst_ip = $dst,
                        b.dst_port = $port,
                        b.proto = $proto,
                        b.cadence = $cadence,
                        b.expected_volume_per_hour = $vol,
                        b.burst_anomaly_threshold = $burst,
                        b.criticality_to_business = $crit,
                        b.production_description = $description,
                        b.if_disrupted = $disrupt
                    """,
                    name=b.name,
                    src_zone=b.src_zone,
                    src=b.src_ip,
                    dst_zone=b.dst_zone,
                    dst=b.dst_ip,
                    port=b.dst_port,
                    proto=b.proto,
                    cadence=b.cadence,
                    vol=b.expected_volume_per_hour,
                    burst=b.burst_anomaly_threshold,
                    crit=b.criticality_to_business.value,
                    description=b.production_description,
                    disrupt=b.if_disrupted,
                )
                counts["nodes"] += 1

            # ── Singleton :KnowledgeMeta — anomalous patterns + steady state ─
            await sess.run(
                """
                MERGE (m:KnowledgeMeta {key: 'baseline_constants'})
                SET m.kg_managed = true,
                    m.steady_state_flows_per_minute = $sf,
                    m.mgt_audit_alert_rate_per_minute = $ar,
                    m.anomalous_patterns = $ap
                """,
                sf=baselines_data["steady_state_flows_per_minute"],
                ar=baselines_data["mgt_audit_alert_rate_per_minute"],
                ap=list(baselines_data["anomalous_patterns"]),
            )
            counts["nodes"] += 1

            # ── Enforcement plane: ApiEndpoint nodes ─────────────────────────
            for endpoint, desc in ep["endpoint_contracts"].items():
                await sess.run(
                    """
                    MERGE (e:ApiEndpoint {endpoint: $ep})
                    SET e.kg_managed = true,
                        e.description = $desc
                    """,
                    ep=endpoint,
                    desc=desc,
                )
                counts["nodes"] += 1

            # ── Critical gotchas ─────────────────────────────────────────────
            for idx, gotcha in enumerate(ep["critical_gotchas"]):
                await sess.run(
                    """
                    MERGE (g:Gotcha {idx: $idx})
                    SET g.kg_managed = true,
                        g.text = $text
                    """,
                    idx=idx,
                    text=gotcha,
                )
                counts["nodes"] += 1

            # ── Field name mappings ──────────────────────────────────────────
            for idx, mapping in enumerate(ep["field_name_mapping"]):
                await sess.run(
                    """
                    MERGE (f:FieldMapping {idx: $idx})
                    SET f.kg_managed = true,
                        f.rest_request = $rest,
                        f.yang_gnmi = $yang,
                        f.configdb = $cfg
                    """,
                    idx=idx,
                    rest=mapping["rest_request"],
                    yang=mapping["yang_gnmi"],
                    cfg=mapping["configdb"],
                )
                counts["nodes"] += 1

            # ── Failure modes ────────────────────────────────────────────────
            for fm in ep["failure_modes"]:
                await sess.run(
                    """
                    MERGE (m:FailureMode {name: $name})
                    SET m.kg_managed = true,
                        m.trigger = $trig,
                        m.rest_status = $status,
                        m.body_signature = $body,
                        m.state = $state,
                        m.agent_action = $action
                    """,
                    name=fm["name"],
                    trig=fm["trigger"],
                    status=fm["rest_status"],
                    body=fm["body_signature"],
                    state=fm["state"],
                    action=fm["agent_action"],
                )
                counts["nodes"] += 1

            # ── RBAC contract singleton ──────────────────────────────────────
            await sess.run(
                """
                MERGE (r:KnowledgeMeta {key: 'rbac_contract'})
                SET r.kg_managed = true,
                    r.text = $text
                """,
                text=ep["rbac_contract"],
            )
            counts["nodes"] += 1

            # ── Invariants: NeverBlockEntry per CIDR ─────────────────────────
            for cidr in inv["never_block_cidrs"]:
                await sess.run(
                    """
                    MERGE (n:NeverBlockEntry {cidr: $cidr})
                    SET n.kg_managed = true,
                        n.rationale = $rat
                    """,
                    cidr=cidr,
                    rat=inv["never_block_rationale"].get(cidr, ""),
                )
                counts["nodes"] += 1

            # ── Invariants: KnowledgeMeta singleton for actions + prefixes ───
            await sess.run(
                """
                MERGE (m:KnowledgeMeta {key: 'agent_invariants'})
                SET m.kg_managed = true,
                    m.allowed_agent_actions = $actions,
                    m.protected_comment_prefixes = $protected,
                    m.agent_comment_prefix = $agent_prefix
                """,
                actions=sorted(inv["allowed_agent_actions"]),
                protected=list(inv["protected_comment_prefixes"]),
                agent_prefix=inv["agent_comment_prefix"],
            )
            counts["nodes"] += 1

        log.info("neo4j_kg_etl_complete", **counts)
        return counts

    # ── Read API used by /kg endpoints ───────────────────────────────────────
    async def stats(self) -> dict[str, Any]:
        """Node + edge counts grouped by label / type."""
        async with self._driver.session() as sess:
            n_total = (await (await sess.run(
                "MATCH (n) WHERE n.kg_managed = true RETURN count(n) AS c"
            )).single())["c"]
            e_total = (await (await sess.run(
                "MATCH ()-[r]->() WHERE r.kg_managed = true RETURN count(r) AS c"
            )).single())["c"]
            by_label_result = await sess.run(
                """
                MATCH (n) WHERE n.kg_managed = true
                UNWIND labels(n) AS L
                RETURN L AS label, count(*) AS c ORDER BY c DESC
                """
            )
            by_label = {r["label"].lower(): r["c"] async for r in by_label_result}
        return {"total_nodes": n_total, "total_edges": e_total, "by_type": by_label}

    async def all_nodes_edges(self) -> dict[str, list]:
        """Full dump for /kg/json + /kg/visualize + /kg/export/graphml."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        async with self._driver.session() as sess:
            n_res = await sess.run(
                "MATCH (n) WHERE n.kg_managed = true "
                "RETURN id(n) AS nid, labels(n) AS labels, properties(n) AS props"
            )
            async for r in n_res:
                props = dict(r["props"])
                props.pop("kg_managed", None)
                nodes.append({
                    "id": r["nid"],
                    "labels": r["labels"],
                    "properties": props,
                })
            e_res = await sess.run(
                "MATCH (s)-[r]->(d) WHERE r.kg_managed = true "
                "RETURN id(s) AS src, id(d) AS dst, type(r) AS type, properties(r) AS props"
            )
            async for r in e_res:
                eprops = dict(r["props"])
                eprops.pop("kg_managed", None)
                edges.append({
                    "source": r["src"],
                    "target": r["dst"],
                    "type": r["type"],
                    "properties": eprops,
                })
        return {"nodes": nodes, "edges": edges}
