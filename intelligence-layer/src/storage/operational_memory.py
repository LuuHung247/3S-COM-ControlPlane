"""Operational memory — aggregate query layer over Postgres decision history.

Returns structured summaries (counts, time buckets, trust score) instead of raw events.
Agent uses these as past-experience context when reasoning about new alerts.
"""
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .postgres import DecisionRecord, PostgresStore

log = structlog.get_logger()


class OperationalMemory:
    """Aggregator over `decisions` table — structured summaries for LLM context."""

    def __init__(self, postgres: PostgresStore) -> None:
        self._pg = postgres

    def _session(self) -> AsyncSession:
        if self._pg._engine is None:
            raise RuntimeError("Postgres not connected")
        return async_sessionmaker(self._pg._engine, expire_on_commit=False)()

    async def get_ip_summary(self, src_ip: str, window_days: int = 30) -> dict:
        """Aggregated summary for src_ip over recent window. Returns structured dict
        suitable for direct injection into LLM prompt."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

        async with self._session() as sess:
            # Total decisions
            total_q = await sess.execute(
                select(func.count()).where(
                    DecisionRecord.alert_src_ip == src_ip,
                    DecisionRecord.created_at >= cutoff,
                )
            )
            total = total_q.scalar() or 0

            if total == 0:
                return {
                    "src_ip": src_ip,
                    "window_days": window_days,
                    "total_alerts": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "distinct_sids": 0,
                    "outcome_breakdown": {},
                    "decision_summary": "first observation in this window",
                    "trust_score": 0.5,   # neutral — no history
                }

            # Distinct SIDs + first/last seen
            stats_q = await sess.execute(
                select(
                    func.count(func.distinct(DecisionRecord.alert_sid)),
                    func.min(DecisionRecord.created_at),
                    func.max(DecisionRecord.created_at),
                ).where(
                    DecisionRecord.alert_src_ip == src_ip,
                    DecisionRecord.created_at >= cutoff,
                )
            )
            distinct_sids, first_seen, last_seen = stats_q.one()

            # Outcome breakdown
            outcome_q = await sess.execute(
                select(DecisionRecord.outcome, func.count())
                .where(
                    DecisionRecord.alert_src_ip == src_ip,
                    DecisionRecord.created_at >= cutoff,
                )
                .group_by(DecisionRecord.outcome)
            )
            outcome_breakdown = {row[0]: row[1] for row in outcome_q.all()}

            # Recent SID frequency
            sid_q = await sess.execute(
                select(DecisionRecord.alert_sid, func.count())
                .where(
                    DecisionRecord.alert_src_ip == src_ip,
                    DecisionRecord.created_at >= cutoff,
                )
                .group_by(DecisionRecord.alert_sid)
                .order_by(func.count().desc())
                .limit(5)
            )
            top_sids = [{"sid": row[0], "count": row[1]} for row in sid_q.all()]

        # Trust score heuristic — count of P1/P2 enforced vs total
        enforced = outcome_breakdown.get("enforced", 0)
        rejected = outcome_breakdown.get("rejected", 0)
        # Lower trust if many enforced; higher trust if rare alerts
        trust_score = max(0.0, min(1.0, 1.0 - (enforced / max(total, 1)) * 0.8))

        # Build decision summary
        decisions_str = ", ".join(f"{k}={v}" for k, v in outcome_breakdown.items())
        sids_str = ", ".join(f"SID {s['sid']}({s['count']}x)" for s in top_sids)

        return {
            "src_ip": src_ip,
            "window_days": window_days,
            "total_alerts": total,
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "distinct_sids": distinct_sids,
            "outcome_breakdown": outcome_breakdown,
            "top_sids": top_sids,
            "decision_summary": f"alerts: {decisions_str}; top SIDs: {sids_str}",
            "trust_score": round(trust_score, 2),
        }

    async def get_recent_alerts_for_correlation(
        self, src_ip: str, window_minutes: int = 10
    ) -> dict:
        """Short-window aggregation for kill-chain correlation. Different from
        get_ip_summary — focuses on recent timing patterns."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        async with self._session() as sess:
            q = await sess.execute(
                select(DecisionRecord.alert_sid, DecisionRecord.created_at)
                .where(
                    DecisionRecord.alert_src_ip == src_ip,
                    DecisionRecord.created_at >= cutoff,
                )
                .order_by(DecisionRecord.created_at.asc())
            )
            rows = q.all()

        if not rows:
            return {
                "src_ip": src_ip,
                "window_minutes": window_minutes,
                "alert_count": 0,
                "sid_sequence": [],
                "kill_chain_signal": "no recent activity",
            }

        sid_sequence = [{"sid": r[0], "ts": r[1].isoformat()} for r in rows]
        unique_sids = sorted(set(r[0] for r in rows))

        # Detect kill chain progression heuristic
        signal = "single-SID activity"
        if len(unique_sids) >= 2:
            severities = []
            for sid in unique_sids:
                if sid in (9000010, 9000011, 9000020):
                    severities.append("recon")
                elif sid in (9000003, 9000004, 9000005):
                    severities.append("lateral")
                elif sid in (9000001, 9000002):
                    severities.append("critical")
            if "recon" in severities and ("lateral" in severities or "critical" in severities):
                signal = "MULTI-STAGE — recon → escalation pattern detected"
            elif "lateral" in severities and "critical" in severities:
                signal = "MULTI-STAGE — lateral → critical pattern detected"
            else:
                signal = f"multi-SID activity ({', '.join(severities)})"

        return {
            "src_ip": src_ip,
            "window_minutes": window_minutes,
            "alert_count": len(rows),
            "unique_sids": unique_sids,
            "sid_sequence": sid_sequence[-10:],   # last 10
            "kill_chain_signal": signal,
        }
