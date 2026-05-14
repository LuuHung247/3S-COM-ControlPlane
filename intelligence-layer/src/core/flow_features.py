"""Flow feature extraction protocol — NetVigil-aligned (NSDI'24 Table 2).

Defines the 9 features per IP-pair × 2-min window the agent computes from
raw `eve.json type:flow` events to reason about east-west anomalies.

Source of truth: knowledge/infra/flow-features.md
"""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class FlowFeatureSet(BaseModel):
    """All YAML blocks from flow-features.md as one container."""

    features_per_ip_pair: list[dict[str, Any]]
    detection_window: dict[str, Any]
    unseen_port_policy: list[dict[str, Any]]
    aggregation_tradeoff: dict[str, Any]
    feature_to_pattern_map: dict[str, Any]


# ─────────────────────────────────────────────────────────────────────────────
# Catalog
# ─────────────────────────────────────────────────────────────────────────────
from . import knowledge_parser as _kp

FEATURE_SET: FlowFeatureSet = _kp.parse_flow_features()


# ─────────────────────────────────────────────────────────────────────────────
# Renderer
# ─────────────────────────────────────────────────────────────────────────────
def _render_features() -> str:
    lines = ["### Feature set per IP-pair (window = 2 min, per NetVigil Table 2)\n"]
    for f in FEATURE_SET.features_per_ip_pair:
        sub = f.get("sub_stats")
        sub_str = f" — sub-stats: {', '.join(sub)}" if sub else ""
        lines.append(
            f"- **{f.get('name')}**{sub_str}: {f.get('description', '')}"
        )
    return "\n".join(lines)


def _render_window() -> str:
    win = FEATURE_SET.detection_window
    return (
        "\n### Detection window\n"
        f"- Default: **{win.get('default_seconds')}s** ({win.get('default_seconds', 120) // 60}-minute aggregation)\n"
        f"- Rationale: {win.get('rationale', '').strip()}"
    )


def _render_unseen_port() -> str:
    lines = ["\n### 'Unseen port' tracking (strong signal for scan/lateral)\n"]
    for entry in FEATURE_SET.unseen_port_policy:
        lines.append(
            f"- Rule: `{entry.get('rule')}` → likely **{entry.get('likely_pattern')}** "
            f"(severity_signal_points: +{entry.get('severity_signal_points', 0)})"
        )
    return "\n".join(lines)


def _render_feature_pattern_map() -> str:
    lines = ["\n### Feature → Pattern mapping\n"]
    for feat, mapping in FEATURE_SET.feature_to_pattern_map.items():
        lines.append(f"- **{feat}**:")
        if isinstance(mapping, dict):
            for k, v in mapping.items():
                lines.append(f"  - {k}: {v}")
        else:
            lines.append(f"  - {mapping}")
    return "\n".join(lines)


def render_for_prompt() -> str:
    """Full feature-extraction reference for the agent."""
    parts = [
        "## FLOW FEATURE EXTRACTION — NetVigil-aligned (IP-pair aggregation)\n",
        "When reasoning about a raw flow event, compute or query these features "
        "for the `(src_ip, dst_ip)` pair within the current 2-min window. Then "
        "match against threat-patterns.md signatures.\n",
        _render_features(),
        _render_window(),
        _render_unseen_port(),
        _render_feature_pattern_map(),
        "\n### Reasoning procedure\n"
        "1. **Aggregate** the incoming flow event into the current 2-min window "
        "by `(src_ip, dst_ip)`.\n"
        "2. **Compute** the 9 features above for that IP pair.\n"
        "3. **Compare** observed features against `baselines.md` for matching "
        "`(src_zone, dst_zone, dst_port)`.\n"
        "4. **Match** to `threat-patterns.md` signatures (top-down by class).\n"
        "5. **Score** severity per `severity-scoring.md`.\n"
        "6. **Decide** action per pattern recommendation + hard overrides.",
    ]
    return "\n".join(parts)
