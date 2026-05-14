"""Severity scoring rubric — deterministic point-based mapping from raw flow
signals to P-level, action, TTL, and confidence calibration.

Used by agent in pure-log mode when no SID pre-classification is available.

Source of truth: knowledge/infra/severity-scoring.md
"""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class SeverityRubric(BaseModel):
    """Container for the 5 YAML blocks in severity-scoring.md."""

    signal_table: dict[str, Any]            # signal_name → {points, rationale}
    severity_mapping: list[dict[str, Any]]  # total_points range → P-level + action
    action_rules: list[dict[str, Any]]      # per-P-level full action spec
    confidence_calibration: dict[str, Any]  # heuristic → confidence range
    hard_overrides: list[dict[str, Any]]    # immutable overrides (NEVER_BLOCK, etc.)


# ─────────────────────────────────────────────────────────────────────────────
# Catalog — populated from knowledge/infra/severity-scoring.md at import.
# ─────────────────────────────────────────────────────────────────────────────
from . import knowledge_parser as _kp

RUBRIC: SeverityRubric = _kp.parse_severity_scoring()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — agent code can call these for deterministic scoring
# ─────────────────────────────────────────────────────────────────────────────
def points_for_signal(signal_name: str) -> int:
    entry = RUBRIC.signal_table.get(signal_name, {})
    return int(entry.get("points", 0))


def p_level_for_points(total_points: int) -> dict[str, Any]:
    """Return the severity_mapping row matching total_points."""
    for row in RUBRIC.severity_mapping:
        tp = row.get("total_points", "")
        if isinstance(tp, str):
            if ">=" in tp:
                threshold = int(tp.replace(">=", "").strip())
                if total_points >= threshold:
                    return row
            elif "-" in tp:
                lo, hi = (int(x.strip()) for x in tp.split("-"))
                if lo <= total_points <= hi:
                    return row
            elif tp.strip().isdigit():
                if total_points == int(tp.strip()):
                    return row
    return RUBRIC.severity_mapping[-1]  # fall back to baseline row


def action_rule(p_level: str) -> dict[str, Any] | None:
    for r in RUBRIC.action_rules:
        if r.get("p_level") == p_level:
            return r
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Renderer
# ─────────────────────────────────────────────────────────────────────────────
def _render_signal_table() -> str:
    lines = ["### Signal Scoring Table\n"]
    for name, entry in RUBRIC.signal_table.items():
        lines.append(f"- `{name}`: +{entry.get('points', 0)} — {entry.get('rationale', '')}")
    return "\n".join(lines)


def _render_severity_mapping() -> str:
    lines = ["\n### Total Points → P-level Mapping\n"]
    for row in RUBRIC.severity_mapping:
        lines.append(
            f"- {row.get('total_points')}: **{row.get('p_level')}** "
            f"({row.get('label')}) — action: `{row.get('action')}` "
            f"TTL {row.get('ttl_seconds')}s notify={row.get('notification_severity')}"
            + (f" — {row['note']}" if row.get("note") else "")
        )
    return "\n".join(lines)


def _render_action_rules() -> str:
    lines = ["\n### Action Rules per P-level\n"]
    for r in RUBRIC.action_rules:
        lines.append(
            f"- **{r.get('p_level')}**: {r.get('primary_action')} "
            f"(TTL {r.get('ttl_seconds')}s, notify={r.get('notify')}, "
            f"escalate_human={r.get('escalate_to_human')}, "
            f"sc_vote={r.get('requires_self_consistency_vote', False)})"
        )
    return "\n".join(lines)


def _render_confidence_calibration() -> str:
    lines = ["\n### Confidence Calibration\n"]
    for k, v in RUBRIC.confidence_calibration.items():
        lines.append(f"- `{k}`: {v}")
    return "\n".join(lines)


def _render_hard_overrides() -> str:
    lines = ["\n### Hard Overrides (immutable)\n"]
    for ov in RUBRIC.hard_overrides:
        lines.append(
            f"- **{ov.get('rule')}** → {ov.get('override_action')} "
            f"(severity: {ov.get('severity', 'n/a')}). {ov.get('rationale', '')}"
        )
    return "\n".join(lines)


def render_for_prompt() -> str:
    """Full rubric render — used for startup verification + per-alert context."""
    parts = [
        "## SEVERITY SCORING RUBRIC — deterministic point-based mapping\n",
        "Apply when no SID pre-classification is present. Sum signal points "
        "from observed flow, map to P-level, pick action.\n",
        _render_signal_table(),
        _render_severity_mapping(),
        _render_action_rules(),
        _render_confidence_calibration(),
        _render_hard_overrides(),
        "\n### Procedure\n"
        "1. Inspect flow event + past_incidents (5-min window).\n"
        "2. Add points per matching signal.\n"
        "3. Map total → P-level → action.\n"
        "4. Apply hard overrides (MGT/NEVER_BLOCK/confidence-gate).\n"
        "5. Calibrate `confidence` field per the heuristics table.\n"
        "6. Output structured `POLICY_DECISION_SCHEMA`.",
    ]
    return "\n".join(parts)
