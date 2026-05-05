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
