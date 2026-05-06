"""Cold storage: audit log with full ReAct trace per decision."""
import json
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped


class Base(DeclarativeBase):
    pass


class DecisionRecord(Base):
    __tablename__ = "decisions"

    id: Mapped[str] = mapped_column(sa.String, primary_key=True)
    alert_sid: Mapped[int] = mapped_column(sa.Integer)
    alert_src_ip: Mapped[str] = mapped_column(sa.String)
    outcome: Mapped[str] = mapped_column(sa.String)
    action: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    confidence: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    rejection_reason: Mapped[str] = mapped_column(sa.Text, default="")
    safety_checks: Mapped[str] = mapped_column(sa.Text, default="{}")  # JSON
    reasoning: Mapped[str] = mapped_column(sa.Text, default="[]")      # JSON list
    hypotheses: Mapped[str] = mapped_column(sa.Text, default="[]")     # JSON list (V2)
    rollback_plan: Mapped[str] = mapped_column(sa.Text, default="{}")  # JSON (V2)
    rule_id: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    ttl_seconds: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    latency_ms: Mapped[float] = mapped_column(sa.Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    dry_run: Mapped[bool] = mapped_column(sa.Boolean, default=True)

    # Retrospective labeling (Phase 4) — populated by background labeler
    retrospective_outcome: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    # Possible values: "true_positive", "false_positive", "recurrence", "inconclusive"
    retrospective_notes: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    labeled_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    # Langfuse trace ID — links decision to observability trace
    trace_id: Mapped[str | None] = mapped_column(sa.String, nullable=True)

    # V3 split — reasoning trace fields populated by Stage 2 LLM call (async)
    primary_hypothesis: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    alternative_actions: Mapped[str] = mapped_column(sa.Text, default="[]")  # JSON list of strings
    follow_up_actions: Mapped[str] = mapped_column(sa.Text, default="[]")    # JSON list of strings
    mitre_technique: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    reasoning_completed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )


class PostgresStore:
    def __init__(self, url: str) -> None:
        self._url = url
        self._engine: AsyncEngine | None = None

    async def connect(self) -> None:
        self._engine = create_async_engine(self._url, pool_pre_ping=True)
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            # Lightweight schema migration for V2 columns (dev-friendly, idempotent)
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS dst_port INTEGER"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS hypotheses TEXT DEFAULT '[]'"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS rollback_plan TEXT DEFAULT '{}'"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS rule_id VARCHAR"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS ttl_seconds INTEGER"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS retrospective_outcome VARCHAR"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS retrospective_notes TEXT"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS labeled_at TIMESTAMPTZ"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS trace_id VARCHAR"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS primary_hypothesis TEXT"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS alternative_actions TEXT DEFAULT '[]'"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS follow_up_actions TEXT DEFAULT '[]'"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR"
            ))
            await conn.execute(sa.text(
                "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS reasoning_completed_at TIMESTAMPTZ"
            ))

    async def close(self) -> None:
        if self._engine:
            await self._engine.dispose()

    async def save_decision(self, data: dict[str, Any]) -> None:
        if self._engine is None:
            return
        async with AsyncSession(self._engine) as session:
            record = DecisionRecord(
                id=data["id"],
                alert_sid=data["alert_sid"],
                alert_src_ip=data["alert_src_ip"],
                outcome=data["outcome"],
                action=data.get("action"),
                src_ip=data.get("src_ip"),
                dst_ip=data.get("dst_ip"),
                dst_port=data.get("dst_port"),
                confidence=data.get("confidence"),
                rejection_reason=data.get("rejection_reason", ""),
                safety_checks=json.dumps(data.get("safety_checks", {})),
                reasoning=json.dumps(data.get("reasoning", [])),
                hypotheses=json.dumps(data.get("hypotheses", [])),
                rollback_plan=json.dumps(data.get("rollback_plan", {})),
                rule_id=data.get("rule_id"),
                ttl_seconds=data.get("ttl_seconds"),
                latency_ms=data.get("latency_ms", 0.0),
                dry_run=data.get("dry_run", True),
                trace_id=data.get("trace_id"),
                primary_hypothesis=data.get("primary_hypothesis"),
                alternative_actions=json.dumps(data.get("alternative_actions", [])),
                follow_up_actions=json.dumps(data.get("follow_up_actions", [])),
                mitre_technique=data.get("mitre_technique"),
                mitre_tactic=data.get("mitre_tactic"),
                reasoning_completed_at=data.get("reasoning_completed_at"),
            )
            session.add(record)
            await session.commit()

    async def update_reasoning(
        self, decision_id: str, reasoning_data: dict[str, Any]
    ) -> bool:
        """Update an existing decision row with V3 reasoning trace fields after the
        Stage 2 LLM call completes (runs async post-enforce). Idempotent."""
        if self._engine is None:
            return False
        async with AsyncSession(self._engine) as session:
            result = await session.execute(
                sa.update(DecisionRecord)
                .where(DecisionRecord.id == decision_id)
                .values(
                    reasoning=json.dumps(reasoning_data.get("reasoning_steps", [])),
                    hypotheses=json.dumps(reasoning_data.get("hypotheses", [])),
                    rollback_plan=json.dumps(reasoning_data.get("rollback_plan", {})),
                    primary_hypothesis=reasoning_data.get("primary_hypothesis"),
                    alternative_actions=json.dumps(reasoning_data.get("alternative_actions", [])),
                    follow_up_actions=json.dumps(reasoning_data.get("follow_up_actions", [])),
                    mitre_technique=reasoning_data.get("mitre_technique"),
                    mitre_tactic=reasoning_data.get("mitre_tactic"),
                    reasoning_completed_at=datetime.now(timezone.utc),
                )
            )
            await session.commit()
            return result.rowcount > 0

    async def get_decision(self, decision_id: str) -> dict[str, Any] | None:
        """Fetch a single decision with all reasoning fields. Used by GET /decisions/{id}."""
        if self._engine is None:
            return None
        async with AsyncSession(self._engine) as session:
            result = await session.execute(
                sa.select(DecisionRecord).where(DecisionRecord.id == decision_id)
            )
            r = result.scalar_one_or_none()
            return _record_to_dict(r) if r else None

    async def list_decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        if self._engine is None:
            return []
        async with AsyncSession(self._engine) as session:
            result = await session.execute(
                sa.select(DecisionRecord)
                .order_by(DecisionRecord.created_at.desc())
                .limit(limit)
            )
            rows = result.scalars().all()
            return [_record_to_dict(r) for r in rows]

    async def ping(self) -> bool:
        try:
            if self._engine is None:
                return False
            async with AsyncSession(self._engine) as session:
                await session.execute(sa.text("SELECT 1"))
            return True
        except Exception:
            return False


def _record_to_dict(r: DecisionRecord) -> dict[str, Any]:
    return {
        "id": r.id,
        "alert_sid": r.alert_sid,
        "alert_src_ip": r.alert_src_ip,
        "outcome": r.outcome,
        "action": r.action,
        "src_ip": r.src_ip,
        "dst_ip": r.dst_ip,
        "dst_port": r.dst_port,
        "confidence": r.confidence,
        "rejection_reason": r.rejection_reason,
        "safety_checks": json.loads(r.safety_checks),
        "reasoning": json.loads(r.reasoning),
        "hypotheses": json.loads(r.hypotheses) if r.hypotheses else [],
        "rollback_plan": json.loads(r.rollback_plan) if r.rollback_plan else {},
        "rule_id": r.rule_id,
        "ttl_seconds": r.ttl_seconds,
        "latency_ms": r.latency_ms,
        "created_at": r.created_at.isoformat(),
        "dry_run": r.dry_run,
        "retrospective_outcome": r.retrospective_outcome,
        "trace_id": r.trace_id,
        "primary_hypothesis": r.primary_hypothesis,
        "alternative_actions": json.loads(r.alternative_actions) if r.alternative_actions else [],
        "follow_up_actions": json.loads(r.follow_up_actions) if r.follow_up_actions else [],
        "mitre_technique": r.mitre_technique,
        "mitre_tactic": r.mitre_tactic,
        "reasoning_completed_at": r.reasoning_completed_at.isoformat() if r.reasoning_completed_at else None,
        "reasoning_loading": r.reasoning_completed_at is None and r.outcome in ("enforced", "dry_run"),
        "retrospective_notes": r.retrospective_notes,
        "labeled_at": r.labeled_at.isoformat() if r.labeled_at else None,
    }
