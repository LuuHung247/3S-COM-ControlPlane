"""KG visualization — render the agent's knowledge graph as interactive HTML.

Builds a heterogeneous NetworkX graph from system_model + threat_playbook + baselines,
exports to pyvis HTML. Use to inspect what the agent "knows" at a glance.

Endpoint: GET /kg/visualize
"""
import os
import tempfile

import networkx as nx
from pyvis.network import Network

from . import system_model
from . import threat_playbook
from . import baselines


_NODE_COLORS = {
    "zone": "#3498db",          # blue
    "asset": "#2ecc71",         # green
    "leaf": "#f39c12",          # orange
    "sid": "#e74c3c",           # red
    "kill_chain": "#9b59b6",    # purple
    "kill_chain_stage": "#c39bd3",
    "baseline": "#1abc9c",      # teal
    "tier": "#7f8c8d",          # grey
}


def build_knowledge_graph() -> nx.MultiDiGraph:
    """Construct full heterogeneous KG."""
    G = nx.MultiDiGraph()

    # Zones
    for zone_name, zone in system_model.ZONES.items():
        G.add_node(
            zone_name,
            type="zone",
            label=f"{zone_name}\n{zone.cidr}",
            title=(
                f"Zone {zone.name}\n"
                f"CIDR: {zone.cidr}\n"
                f"VLAN: {zone.vlan}\n"
                f"SVI: {zone.svi_gateway}\n"
                f"Trust: {zone.trust_level.value}\n"
                f"Criticality: {zone.criticality.value}\n"
                f"Purpose: {zone.purpose}"
            ),
            shape="box",
        )

    # Leafs
    for leaf_name, leaf in system_model.LEAFS.items():
        G.add_node(
            leaf_name,
            type="leaf",
            label=leaf_name,
            title=f"LEAF {leaf_name}\nMgmt: {leaf.mgmt_ip}\nZones: {leaf.zones}\n{leaf.role}",
            shape="diamond",
        )
        for zone_in_leaf in leaf.zones:
            G.add_edge(leaf_name, zone_in_leaf, label="enforces", color="#f39c12")

    # Assets
    for ip, asset in system_model.ASSETS.items():
        G.add_node(
            ip,
            type="asset",
            label=f"{asset.hostname}\n{ip}",
            title=(
                f"Host: {asset.hostname}\n"
                f"IP: {ip}\n"
                f"Tier: {asset.tier}\n"
                f"Criticality: {asset.criticality.value}\n"
                f"Data: {asset.data_classification.value}\n"
                f"Role: {asset.role}\n"
                f"Owner: {asset.owner_team}\n"
                f"If blocked: {asset.if_blocked_impact}"
            ),
            shape="ellipse",
        )
        G.add_edge(ip, asset.zone, label="member_of", color="#2ecc71")

    # Policy matrix (zone-to-zone edges)
    from . import policy
    for (src_zone, dst_zone), verdict in policy.POLICY_MATRIX.items():
        if verdict == "ALLOW":
            G.add_edge(src_zone, dst_zone, label="ALLOW", color="#27ae60", dashes=False)
        else:
            G.add_edge(src_zone, dst_zone, label="DENY", color="#c0392b", dashes=True)

    # SID detections
    for sid, det in threat_playbook.SID_DETECTIONS.items():
        sid_node = f"SID-{sid}"
        G.add_node(
            sid_node,
            type="sid",
            label=f"SID {sid}\nP{det.severity_p_level}",
            title=(
                f"SID {sid} (P{det.severity_p_level})\n"
                f"Signature: {det.signature_msg}\n"
                f"Tactic: {det.mitre_tactic}\n"
                f"Technique: {det.mitre_technique}\n"
                f"Detection: {det.detection_logic}\n"
                f"Response: {det.recommended_response}\n"
                f"FP likelihood: {det.false_positive_likelihood}"
            ),
            shape="triangle",
        )

    # Kill chains and stages
    for kc in threat_playbook.KILL_CHAINS:
        kc_node = kc.name
        G.add_node(
            kc_node,
            type="kill_chain",
            label=kc.name.replace("-", "\n"),
            title=(
                f"Kill chain: {kc.name}\n\n"
                f"{kc.production_description}\n\n"
                f"Dwell: {kc.typical_dwell_between_stages}\n"
                f"Intervention: {kc.recommended_intervention_point}\n"
                f"Containment: {kc.containment_strategy}"
            ),
            shape="star",
        )
        for stage in kc.stages:
            for sid in stage.expected_signals:
                G.add_edge(
                    f"SID-{sid}",
                    kc_node,
                    label=f"stage{stage.stage}",
                    color="#9b59b6",
                )

    # Baselines (production traffic patterns)
    for b in baselines.ALL_BASELINES:
        baseline_node = f"flow:{b.name}"
        G.add_node(
            baseline_node,
            type="baseline",
            label=b.name.replace("-", "\n"),
            title=(
                f"Baseline flow: {b.name}\n\n"
                f"{b.production_description}\n\n"
                f"Cadence: {b.cadence}\n"
                f"Volume: ~{b.expected_volume_per_hour}/hr\n"
                f"Criticality: {b.criticality_to_business.value}\n"
                f"If disrupted: {b.if_disrupted}"
            ),
            shape="hexagon",
        )
        # Connect baseline to source asset and dest asset (if known)
        if b.src_ip in system_model.ASSETS:
            G.add_edge(b.src_ip, baseline_node, label="originates", color="#1abc9c")
        if b.dst_ip in system_model.ASSETS:
            G.add_edge(baseline_node, b.dst_ip, label=f":{b.dst_port}", color="#1abc9c")

    return G


def render_html(out_path: str | None = None) -> str:
    """Render KG to interactive HTML. Returns path written."""
    G = build_knowledge_graph()

    net = Network(
        height="900px",
        width="100%",
        directed=True,
        notebook=False,
        cdn_resources="in_line",
        bgcolor="#fafafa",
    )
    net.from_nx(G)

    # Color nodes by type
    for node in net.nodes:
        ntype = node.get("type", "")
        node["color"] = _NODE_COLORS.get(ntype, "#95a5a6")

    # Physics tuning
    net.set_options("""
    {
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -8000,
          "centralGravity": 0.3,
          "springLength": 200,
          "springConstant": 0.04,
          "damping": 0.09
        },
        "minVelocity": 0.5
      },
      "nodes": {
        "font": {"size": 12, "face": "monospace"}
      },
      "edges": {
        "font": {"size": 10},
        "smooth": {"type": "continuous"}
      }
    }
    """)

    if out_path is None:
        fd, out_path = tempfile.mkstemp(suffix=".html", prefix="kg_")
        os.close(fd)

    net.save_graph(out_path)
    return out_path


def render_html_string() -> str:
    """Render KG and return HTML content as string."""
    path = render_html()
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        os.unlink(path)
    except OSError:
        pass
    return content


# ─────────────────────────────────────────────────────────────────────────────
# Neo4j-sourced render — used when Neo4jKG is the active KG store
# (Pydantic models are still source-of-truth, but reads come from Neo4j).
# ─────────────────────────────────────────────────────────────────────────────
def graph_from_neo4j_dump(dump: dict) -> nx.MultiDiGraph:
    """Build a NetworkX MultiDiGraph from `Neo4jKG.all_nodes_edges()` dump.

    Mapping:
      Neo4j label (PascalCase) → KG node `type` (snake_case to match FE filter
      keys + color palette). e.g. KillChain → kill_chain.
      Asset uses `ip` as node id; everything else uses `name` or `sid`.
    """
    # Neo4j label → FE/KG type name (legacy NetworkX builder convention)
    LABEL_TO_TYPE = {
        "Zone": "zone", "Asset": "asset", "Leaf": "leaf",
        "Sid": "sid", "KillChain": "kill_chain", "Baseline": "baseline",
    }

    G = nx.MultiDiGraph()
    for n in dump.get("nodes", []):
        labels = n.get("labels") or []
        ntype = LABEL_TO_TYPE.get(labels[0], labels[0].lower()) if labels else "unknown"
        props = n.get("properties", {})
        # Choose stable node id matching legacy NetworkX builder
        nid = (
            props.get("ip") if ntype == "asset" else
            f"SID-{props.get('sid')}" if ntype == "sid" else
            f"flow:{props.get('name')}" if ntype == "baseline" else
            props.get("name") or props.get("ip") or str(n.get("id"))
        )
        # Compose human-readable title (hover tooltip)
        title_lines = [f"{ntype}: {nid}"]
        for k, v in props.items():
            if k in ("ip", "name", "sid"):
                continue
            title_lines.append(f"{k}: {v}")
        label = props.get("name") or props.get("hostname") or str(nid)
        if ntype == "sid":
            label = f"SID {props.get('sid')}\nP{props.get('severity_p_level','?')}"
        elif ntype == "asset":
            label = f"{props.get('hostname','?')}\n{props.get('ip','?')}"
        elif ntype == "zone":
            label = f"{props.get('name','?')}\n{props.get('cidr','?')}"
        shape = {
            "zone": "box", "leaf": "diamond", "asset": "ellipse",
            "sid": "triangle", "kill_chain": "star", "baseline": "hexagon",
        }.get(ntype, "ellipse")
        G.add_node(nid, type=ntype, label=label, title="\n".join(title_lines), shape=shape)

    # Build id-mapping for edges (Neo4j internal id → our nid)
    id_to_nid: dict[int, str] = {}
    for n in dump.get("nodes", []):
        labels = n.get("labels") or []
        ntype = LABEL_TO_TYPE.get(labels[0], labels[0].lower()) if labels else "unknown"
        props = n.get("properties", {})
        nid = (
            props.get("ip") if ntype == "asset" else
            f"SID-{props.get('sid')}" if ntype == "sid" else
            f"flow:{props.get('name')}" if ntype == "baseline" else
            props.get("name") or props.get("ip") or str(n.get("id"))
        )
        id_to_nid[n["id"]] = nid

    for e in dump.get("edges", []):
        src = id_to_nid.get(e["source"])
        dst = id_to_nid.get(e["target"])
        if src is None or dst is None:
            continue
        rtype = e.get("type", "")
        eprops = e.get("properties", {})
        if rtype == "ALLOW":
            G.add_edge(src, dst, label="ALLOW", color="#27ae60")
        elif rtype == "DENY":
            G.add_edge(src, dst, label="DENY", color="#c0392b")
        elif rtype == "MEMBER_OF":
            G.add_edge(src, dst, label="member_of", color="#2ecc71")
        elif rtype == "ENFORCES":
            G.add_edge(src, dst, label="enforces", color="#f39c12")
        elif rtype == "EXPECTED_IN":
            stage = eprops.get("stage", "")
            G.add_edge(src, dst, label=f"stage{stage}", color="#9b59b6")
        else:
            G.add_edge(src, dst, label=rtype.lower(), color="#95a5a6")
    return G


def render_html_from_neo4j(dump: dict) -> str:
    """Render KG HTML from Neo4j dump. Same physics/styling as legacy render."""
    G = graph_from_neo4j_dump(dump)
    net = Network(
        height="900px", width="100%", directed=True, notebook=False,
        cdn_resources="in_line", bgcolor="#fafafa",
    )
    net.from_nx(G)
    for node in net.nodes:
        ntype = node.get("type", "")
        node["color"] = _NODE_COLORS.get(ntype, "#95a5a6")
    net.set_options("""
    {
      "physics": {"barnesHut": {"gravitationalConstant": -8000, "centralGravity": 0.3,
        "springLength": 200, "springConstant": 0.04, "damping": 0.09}, "minVelocity": 0.5},
      "nodes": {"font": {"size": 12, "face": "monospace"}},
      "edges": {"font": {"size": 10}, "smooth": {"type": "continuous"}}
    }
    """)
    fd, out_path = tempfile.mkstemp(suffix=".html", prefix="kg_neo4j_")
    os.close(fd)
    net.save_graph(out_path)
    with open(out_path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        os.unlink(out_path)
    except OSError:
        pass
    return content
