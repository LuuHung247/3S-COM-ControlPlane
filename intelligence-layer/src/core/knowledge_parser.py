"""Parse knowledge/infra/*.md → typed Pydantic objects.

Each .md file contains zero or more ```yaml ... ``` fenced code blocks. Each block
holds the canonical data for one entity (Zone, Asset, etc.). Prose around blocks
is human-facing and is ignored by the parser.

Failure mode: invalid YAML, missing required field, or wrong type → Pydantic
ValidationError raised. Parser is fail-closed; one bad block aborts the entire
file load to avoid partial/inconsistent state in Neo4j.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

# NOTE: Pydantic schema classes are imported INSIDE each parse_* function below.
# Deferred imports break the circular dependency: core/system_model.py wants to
# call parse_zones() at module-load time, but parse_zones() needs Zone — which
# is defined in system_model.py. By deferring the import to call-time, both
# modules can coexist; system_model.py finishes loading (defining Zone) before
# the first parse_zones() call evaluates the deferred import.


KNOWLEDGE_DIR = Path(__file__).resolve().parents[2] / "knowledge" / "infra"

_YAML_BLOCK = re.compile(r"^```yaml\s*\n(.*?)^```\s*$", re.MULTILINE | re.DOTALL)


def _yaml_blocks(md_path: Path) -> list[Any]:
    """Extract every ```yaml fenced block from a markdown file."""
    if not md_path.exists():
        raise FileNotFoundError(f"Knowledge file missing: {md_path}")
    text = md_path.read_text(encoding="utf-8")
    return [yaml.safe_load(m.group(1)) for m in _YAML_BLOCK.finditer(text)]


# ─────────────────────────────────────────────────────────────────────────────
# Per-file typed parsers
# ─────────────────────────────────────────────────────────────────────────────
def parse_zones() -> dict[str, "Zone"]:
    from .system_model import Zone
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "zones.md")
    return {b["name"]: Zone(**b) for b in blocks}


def parse_assets() -> dict[str, "Asset"]:
    from .system_model import Asset
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "assets.md")
    return {b["ip"]: Asset(**b) for b in blocks}


def parse_leafs() -> dict[str, "Leaf"]:
    from .system_model import Leaf
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "leafs.md")
    return {b["name"]: Leaf(**b) for b in blocks}


def parse_baselines() -> dict[str, Any]:
    """Returns {patterns, anomalous_patterns, steady_state_flows_per_minute,
    mgt_audit_alert_rate_per_minute}."""
    from .baselines import TrafficPattern
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "baselines.md")
    constants_block: dict | None = None
    anomalous_block: dict | None = None
    patterns: list[TrafficPattern] = []
    for b in blocks:
        if not isinstance(b, dict):
            continue
        if "steady_state_flows_per_minute" in b:
            constants_block = b
        elif "anomalous_patterns" in b:
            anomalous_block = b
        elif "name" in b and "src_ip" in b:
            patterns.append(TrafficPattern(**b))
    if constants_block is None:
        raise ValueError("baselines.md missing constants block "
                         "(steady_state_flows_per_minute / mgt_audit_alert_rate_per_minute)")
    if anomalous_block is None:
        raise ValueError("baselines.md missing anomalous_patterns block")
    return {
        "patterns": patterns,
        "anomalous_patterns": list(anomalous_block["anomalous_patterns"]),
        "steady_state_flows_per_minute": int(constants_block["steady_state_flows_per_minute"]),
        "mgt_audit_alert_rate_per_minute": int(constants_block["mgt_audit_alert_rate_per_minute"]),
    }


def parse_policy_matrix() -> dict[tuple[str, str], str]:
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "policy-matrix.md")
    for b in blocks:
        if isinstance(b, dict) and "policy_matrix" in b:
            out: dict[tuple[str, str], str] = {}
            for row in b["policy_matrix"]:
                out[(row["src_zone"], row["dst_zone"])] = row["verdict"]
            return out
    raise ValueError("policy-matrix.md has no `policy_matrix` block")


def parse_sids() -> dict[int, "SidDetection"]:
    from .threat_playbook import SidDetection
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "sids.md")
    return {b["sid"]: SidDetection(**b) for b in blocks}


def parse_kill_chains() -> list["KillChain"]:
    from .threat_playbook import KillChain
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "kill-chains.md")
    return [KillChain(**b) for b in blocks]


def parse_enforcement_plane() -> dict[str, Any]:
    """Returns {endpoint_contracts, field_name_mapping, critical_gotchas, failure_modes,
    rbac_contract}."""
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "enforcement-plane.md")
    out: dict[str, Any] = {}
    for b in blocks:
        if not isinstance(b, dict):
            continue
        out.update(b)
    expected = {"endpoint_contracts", "field_name_mapping", "critical_gotchas",
                "failure_modes", "rbac_contract"}
    missing = expected - out.keys()
    if missing:
        raise ValueError(f"enforcement-plane.md missing blocks: {missing}")
    # Normalize endpoint_contracts list-of-dict → dict
    ec = {row["endpoint"]: row["description"] for row in out["endpoint_contracts"]}
    out["endpoint_contracts"] = ec
    return out


def parse_threat_patterns() -> dict[str, Any]:
    """Parse threat-patterns.md → list[ThreatPattern] + difficulty tiers + insights.

    Returns: {patterns, detection_difficulty_tiers, insights}
    """
    from .threat_patterns import ThreatPattern
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "threat-patterns.md")
    patterns: list[ThreatPattern] = []
    difficulty_tiers: dict[str, Any] = {}
    insights: list[dict[str, Any]] = []
    for b in blocks:
        if not isinstance(b, dict):
            continue
        if "id" in b and "threat_class" in b and "flow_signature" in b:
            patterns.append(ThreatPattern(**b))
        elif "detection_difficulty_tiers" in b:
            difficulty_tiers = b["detection_difficulty_tiers"]
        elif "insights" in b:
            insights = list(b["insights"])
    if not patterns:
        raise ValueError("threat-patterns.md has no pattern blocks")
    return {
        "patterns": patterns,
        "detection_difficulty_tiers": difficulty_tiers,
        "insights": insights,
    }


def parse_severity_scoring() -> "SeverityRubric":
    """Parse severity-scoring.md → SeverityRubric (5 YAML blocks merged)."""
    from .severity_scoring import SeverityRubric
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "severity-scoring.md")
    merged: dict[str, Any] = {}
    for b in blocks:
        if not isinstance(b, dict):
            continue
        merged.update(b)
    expected = {"signal_table", "severity_mapping", "action_rules",
                "confidence_calibration", "hard_overrides"}
    missing = expected - merged.keys()
    if missing:
        raise ValueError(f"severity-scoring.md missing blocks: {missing}")
    return SeverityRubric(**{k: merged[k] for k in expected})


def parse_flow_features() -> "FlowFeatureSet":
    """Parse flow-features.md → FlowFeatureSet."""
    from .flow_features import FlowFeatureSet
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "flow-features.md")
    merged: dict[str, Any] = {}
    for b in blocks:
        if not isinstance(b, dict):
            continue
        merged.update(b)
    return FlowFeatureSet(
        features_per_ip_pair=merged.get("features_per_ip_pair", []),
        detection_window=merged.get("detection_window", {}),
        unseen_port_policy=merged.get("policy", []),
        aggregation_tradeoff=merged.get("aggregation_tradeoff", {}),
        feature_to_pattern_map=merged.get("feature_to_pattern_map", {}),
    )


def parse_invariants() -> dict[str, Any]:
    """Returns {never_block_cidrs, never_block_rationale, allowed_agent_actions,
    protected_comment_prefixes, agent_comment_prefix, agent_priority_min/max}."""
    blocks = _yaml_blocks(KNOWLEDGE_DIR / "invariants.md")
    out: dict[str, Any] = {}
    for b in blocks:
        if not isinstance(b, dict):
            continue
        out.update(b)
    if "never_block" not in out:
        raise ValueError("invariants.md missing `never_block` block")
    cidrs: list[str] = []
    rationale: dict[str, str] = {}
    for row in out["never_block"]:
        cidrs.append(row["cidr"])
        rationale[row["cidr"]] = row.get("rationale", "")
    return {
        "never_block_cidrs": cidrs,
        "never_block_rationale": rationale,
        "allowed_agent_actions": frozenset(out.get("allowed_agent_actions", ["DROP"])),
        "protected_comment_prefixes": list(out.get("protected_comment_prefixes", [])),
        "agent_comment_prefix": out.get("agent_comment_prefix", "nos:agent-"),
        "agent_priority_min": out.get("agent_priority_min"),
        "agent_priority_max": out.get("agent_priority_max"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Composite loader
# ─────────────────────────────────────────────────────────────────────────────
def parse_all() -> dict[str, Any]:
    """Parse every .md in knowledge/infra/. Raises on any validation failure."""
    return {
        "zones": parse_zones(),
        "assets": parse_assets(),
        "leafs": parse_leafs(),
        "baselines": parse_baselines(),
        "policy_matrix": parse_policy_matrix(),
        "sids": parse_sids(),
        "kill_chains": parse_kill_chains(),
        "enforcement_plane": parse_enforcement_plane(),
        "invariants": parse_invariants(),
        "threat_patterns": parse_threat_patterns(),
        "severity_scoring": parse_severity_scoring(),
        "flow_features": parse_flow_features(),
    }
