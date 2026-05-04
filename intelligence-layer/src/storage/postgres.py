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
    confidence: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    rejection_reason: Mapped[str] = mapped_column(sa.Text, default="")
    safety_checks: Mapped[str] = mapped_column(sa.Text, default="{}")  # JSON
    reasoning: Mapped[str] = mapped_column(sa.Text, default="[]")      # JSON list
    latency_ms: Mapped[float] = mapped_column(sa.Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    dry_run: Mapped[bool] = mapped_column(sa.Boolean, default=True)


class PostgresStore:
    def __init__(self, url: str) -> None:
        self._url = url
        self._engine: AsyncEngine | None = None

    async def connect(self) -> None:
        self._engine = create_async_engine(self._url, pool_pre_ping=True)
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        if self._engine:
            await self._engine.dispose()

    async def save_decision(self, data: dict[str, Any]) -> None:
        if self._engine is None:
            return
        async with AsyncSession(self._engine) as session:
            intent = data.get("intent") or {}
            record = DecisionRecord(
                id=data["id"],
                alert_sid=data["alert_sid"],
                alert_src_ip=data["alert_src_ip"],
                outcome=data["outcome"],
                action=intent.get("action"),
                src_ip=intent.get("src_ip"),
                dst_ip=intent.get("dst_ip"),
                confidence=intent.get("confidence"),
                rejection_reason=data.get("rejection_reason", ""),
                safety_checks=json.dumps(data.get("safety_checks", {})),
                reasoning=json.dumps(intent.get("reasoning_steps", [])),
                latency_ms=data.get("latency_ms", 0.0),
                dry_run=data.get("dry_run", True),
            )
            session.add(record)
            await session.commit()

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
        "confidence": r.confidence,
        "rejection_reason": r.rejection_reason,
        "safety_checks": json.loads(r.safety_checks),
        "reasoning": json.loads(r.reasoning),
        "latency_ms": r.latency_ms,
        "created_at": r.created_at.isoformat(),
        "dry_run": r.dry_run,
    }
