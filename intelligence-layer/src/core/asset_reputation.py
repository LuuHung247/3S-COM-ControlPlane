"""Asset reputation — runtime behavioral score per src_ip from retrospective labels.

Closes the learning loop:
  IncidentLabeler writes retrospective_outcome to Postgres
       ↓
  This module reads recent labels, computes reputation score
       ↓
  Score injected into per-alert prompt so LLM sees "web-01 has 3 TP in last 1h"

Different from OperationalMemory.get_ip_summary (30-day trust_score):
  - Window: 1 hour by default (recent behavioral signal, not lifetime stats)
  - Output: scored 0..1 + evidence string + risk band, ready to render
  - Decays: more recent labels weighted higher

Score formula (clamped to [0, 1]):
  score = 1.0 - 0.20 * tp_count - 0.10 * recur_count + 0.15 * fp_count

Lower score = more confirmed bad behavior recently. LLM uses this to
escalate confidence on next decision for the same IP.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..storage.postgres import DecisionRecord, PostgresStore


# ─────────────────────────────────────────────────────────────────────────────
# Tunables
# ─────────────────────────────────────────────────────────────────────────────
TP_PENALTY: float = 0.20      # each confirmed true positive lowers reputation
RECUR_PENALTY: float = 0.10   # each recurrence (block didn't stick) lowers more mildly
FP_BONUS: float = 0.15        # each false positive raises reputation (agent over-blocked)
INCONCLUSIVE_PENALTY: float = 0.05

NEUTRAL_SCORE: float = 1.00   # No history → fully trusted (don't penalize unknown IPs)
DEFAULT_WINDOW_HOURS: int = 1


# ─────────────────────────────────────────────────────────────────────────────
# Data shape
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class AssetReputation:
    """Runtime behavioral reputation for a single src_ip in a time window."""
    src_ip: str
    window_hours: int
    score: float                  # 0.0 (very bad) .. 1.0 (clean)
    band: str                     # "clean" | "neutral" | "low" | "very_low"
    tp_count: int
    fp_count: int
    recurrence_count: int
    inconclusive_count: int
    total_decisions: int
    has_history: bool
    evidence: str                 # one-line human readable
    last_seen: datetime | None

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "window_hours": self.window_hours,
            "score": self.score,
            "band": self.band,
            "tp_count": self.tp_count,
            "fp_count": self.fp_count,
            "recurrence_count": self.recurrence_count,
            "inconclusive_count": self.inconclusive_count,
            "total_decisions": self.total_decisions,
            "has_history": self.has_history,
            "evidence": self.evidence,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


def _classify_band(score: float) -> str:
    if score >= 0.85:
        return "clean"
    if score >= 0.60:
        return "neutral"
    if score >= 0.30:
        return "low"
    return "very_low"


def compute_score(
    tp: int,
    fp: int,
    recur: int,
    inconclusive: int = 0,
) -> float:
    """Pure formula — exposed separately for unit tests."""
    raw = (
        NEUTRAL_SCORE
        - TP_PENALTY * tp
        - RECUR_PENALTY * recur
        - INCONCLUSIVE_PENALTY * inconclusive
        + FP_BONUS * fp
    )
    return max(0.0, min(1.0, raw))


# ─────────────────────────────────────────────────────────────────────────────
# Postgres aggregation
# ─────────────────────────────────────────────────────────────────────────────
async def fetch_reputation(
    postgres: PostgresStore,
    src_ip: str,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> AssetReputation:
    """Query labelled decisions from Postgres in window, compute reputation."""
    if postgres._engine is None:
        return _empty_reputation(src_ip, window_hours)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    async with async_sessionmaker(postgres._engine, expire_on_commit=False)() as sess:
        # Aggregate retrospective_outcome counts
        result = await sess.execute(
            select(
                DecisionRecord.retrospective_outcome,
                func.count(),
                func.max(DecisionRecord.created_at),
            )
            .where(
                DecisionRecord.alert_src_ip == src_ip,
                DecisionRecord.created_at >= cutoff,
            )
            .group_by(DecisionRecord.retrospective_outcome)
        )
        rows = result.all()

    counts = {"true_positive": 0, "false_positive": 0, "recurrence": 0, "inconclusive": 0, None: 0}
    last_seen: datetime | None = None
    for outcome, count, max_ts in rows:
        key = outcome if outcome in counts else None
        counts[key] = counts.get(key, 0) + (count or 0)
        if max_ts is not None and (last_seen is None or max_ts > last_seen):
            last_seen = max_ts

    tp = counts.get("true_positive", 0)
    fp = counts.get("false_positive", 0)
    recur = counts.get("recurrence", 0)
    inconclusive = counts.get("inconclusive", 0)
    unlabeled = counts.get(None, 0)
    labelled_total = tp + fp + recur + inconclusive
    total = labelled_total + unlabeled

    score = compute_score(tp, fp, recur, inconclusive)
    has_history = total > 0
    if not has_history:
        score = NEUTRAL_SCORE

    band = _classify_band(score)

    if not has_history:
        evidence = "no past decisions for this IP in window"
    elif labelled_total == 0:
        evidence = (
            f"{unlabeled} decision(s) in last {window_hours}h not yet retrospectively labelled"
        )
    else:
        parts = []
        if tp:
            parts.append(f"{tp} TP")
        if recur:
            parts.append(f"{recur} recurrences")
        if fp:
            parts.append(f"{fp} FP")
        if inconclusive:
            parts.append(f"{inconclusive} inconclusive")
        if unlabeled:
            parts.append(f"{unlabeled} unlabelled")
        evidence = f"{' / '.join(parts)} in last {window_hours}h"

    return AssetReputation(
        src_ip=src_ip,
        window_hours=window_hours,
        score=round(score, 2),
        band=band,
        tp_count=tp,
        fp_count=fp,
        recurrence_count=recur,
        inconclusive_count=inconclusive,
        total_decisions=total,
        has_history=has_history,
        evidence=evidence,
        last_seen=last_seen,
    )


def _empty_reputation(src_ip: str, window_hours: int) -> AssetReputation:
    return AssetReputation(
        src_ip=src_ip,
        window_hours=window_hours,
        score=NEUTRAL_SCORE,
        band="clean",
        tp_count=0,
        fp_count=0,
        recurrence_count=0,
        inconclusive_count=0,
        total_decisions=0,
        has_history=False,
        evidence="postgres unavailable — neutral default",
        last_seen=None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Render — produce a 2-3 line snippet for prompt injection
# ─────────────────────────────────────────────────────────────────────────────
def render_for_prompt(rep: AssetReputation) -> str:
    """Format reputation for LLM consumption — short, evidence-first."""
    if not rep.has_history:
        return (
            f"### Runtime reputation ({rep.src_ip}, last {rep.window_hours}h)\n"
            f"- score: **{rep.score:.2f}** ({rep.band}) — first observation, no learning signal yet"
        )

    interpretation = {
        "clean": "no concerning behavioral signal",
        "neutral": "mixed signal — proceed with normal vigilance",
        "low": "RECENT BAD BEHAVIOR — agent has confirmed real threats from this IP. Higher prior toward DROP",
        "very_low": "REPEAT OFFENDER — multiple confirmed incidents within the window. Strong prior toward DROP",
    }[rep.band]

    return (
        f"### Runtime reputation ({rep.src_ip}, last {rep.window_hours}h)\n"
        f"- score: **{rep.score:.2f}** ({rep.band}) — {rep.evidence}\n"
        f"- interpretation: {interpretation}"
    )
