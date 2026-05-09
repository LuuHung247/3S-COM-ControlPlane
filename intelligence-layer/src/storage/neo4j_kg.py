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

    # ── ETL: Pydantic models → Neo4j ─────────────────────────────────────────
    async def reload_from_models(self) -> dict[str, int]:
        """Idempotent reload: WIPE + RECREATE from current Pydantic models.

        Called at container startup. Returns counts of nodes/edges created.
        """
        from ..core import system_model, threat_playbook, baselines, policy

        async with self._driver.session() as sess:
            # WIPE everything we own (labelled to avoid clobbering user data)
            await sess.run("MATCH (n) WHERE n.kg_managed = true DETACH DELETE n")

            counts = {"nodes": 0, "edges": 0}

            # ── Zones ────────────────────────────────────────────────────────
            for zone_name, zone in system_model.ZONES.items():
                await sess.run(
                    """
                    MERGE (z:Zone {name: $name})
                    SET z.kg_managed = true,
                        z.cidr = $cidr,
                        z.vlan = $vlan,
                        z.svi_gateway = $svi,
                        z.trust_level = $trust,
                        z.criticality = $crit,
                        z.purpose = $purpose
                    """,
                    name=zone_name,
                    cidr=zone.cidr,
                    vlan=zone.vlan,
                    svi=zone.svi_gateway,
                    trust=zone.trust_level.value,
                    crit=zone.criticality.value,
                    purpose=zone.purpose,
                )
                counts["nodes"] += 1

            # ── Leafs (with ENFORCES edges) ──────────────────────────────────
            for leaf_name, leaf in system_model.LEAFS.items():
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
            for ip, asset in system_model.ASSETS.items():
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
                        a.if_blocked_impact = $impact,
                        a.zone = $zone
                    """,
                    ip=ip,
                    hostname=asset.hostname,
                    tier=asset.tier,
                    crit=asset.criticality.value,
                    dc=asset.data_classification.value,
                    role=asset.role,
                    owner=asset.owner_team,
                    impact=asset.if_blocked_impact,
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
            for (src_zone, dst_zone), verdict in policy.POLICY_MATRIX.items():
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
            for sid, det in threat_playbook.SID_DETECTIONS.items():
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
                        s.recommended_response = $resp,
                        s.default_ttl_seconds = $ttl,
                        s.false_positive_likelihood = $fp
                    """,
                    sid=sid,
                    sev=det.severity_p_level,
                    msg=det.signature_msg,
                    desc=det.production_description,
                    tactic=det.mitre_tactic,
                    technique=det.mitre_technique,
                    logic=det.detection_logic,
                    resp=det.recommended_response,
                    ttl=det.default_ttl_seconds,
                    fp=det.false_positive_likelihood,
                )
                counts["nodes"] += 1

            # ── KillChains + Stages (PART_OF + EXPECTED_IN edges) ────────────
            for kc in threat_playbook.KILL_CHAINS:
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
                                r.indicators = $ind
                            """,
                            sid=sid,
                            kc=kc.name,
                            stage=stage.stage,
                            tactic=stage.tactic,
                            ind=stage.production_indicators,
                        )
                        counts["edges"] += 1

            # ── Baselines (legitimate flows) ─────────────────────────────────
            for b in baselines.ALL_BASELINES:
                await sess.run(
                    """
                    MERGE (b:Baseline {name: $name})
                    SET b.kg_managed = true,
                        b.src_ip = $src,
                        b.dst_ip = $dst,
                        b.dst_port = $port,
                        b.proto = $proto,
                        b.criticality = $crit,
                        b.cadence = $cadence,
                        b.production_description = $description,
                        b.if_disrupted = $disrupt
                    """,
                    name=b.name,
                    src=b.src_ip,
                    dst=b.dst_ip,
                    port=b.dst_port,
                    proto=b.proto,
                    crit=b.criticality_to_business.value,
                    cadence=b.cadence,
                    description=b.production_description,
                    disrupt=b.if_disrupted,
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
