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

    # P2: pgvector embedding for semantic similarity search.
    # Defined as untyped column at ORM level to keep `pgvector` import optional;
    # the actual VECTOR(384) type is enforced by the migration in connect().
    # Writes happen in a background task post-save_decision.


class DecisionHistoryRecord(Base):
    """Mirror of DecisionRecord — same schema. Audit-only, FE reads from this table.

    Lifecycle:
      - INSERT on every save_decision (dual-write with the workspace `decisions` table).
      - UPDATE retrospective_outcome on every IncidentLabeler tick.
      - UPDATE embedding on every embed-on-write.
      - NEVER truncated by eval scripts — preserves history across experiments.

    Schema must stay 1:1 with DecisionRecord. If a column is added there, add it here too.
    """
    __tablename__ = "decisions_history"

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
    safety_checks: Mapped[str] = mapped_column(sa.Text, default="{}")
    reasoning: Mapped[str] = mapped_column(sa.Text, default="[]")
    hypotheses: Mapped[str] = mapped_column(sa.Text, default="[]")
    rollback_plan: Mapped[str] = mapped_column(sa.Text, default="{}")
    rule_id: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    ttl_seconds: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    latency_ms: Mapped[float] = mapped_column(sa.Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    dry_run: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    retrospective_outcome: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    retrospective_notes: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    labeled_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    trace_id: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    primary_hypothesis: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    alternative_actions: Mapped[str] = mapped_column(sa.Text, default="[]")
    follow_up_actions: Mapped[str] = mapped_column(sa.Text, default="[]")
    mitre_technique: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(sa.String, nullable=True)
    reasoning_completed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    # embedding column added via SQL migration (pgvector type)


class PostgresStore:
    def __init__(self, url: str) -> None:
        self._url = url
        self._engine: AsyncEngine | None = None

    async def connect(self) -> None:
        self._engine = create_async_engine(self._url, pool_pre_ping=True)
        async with self._engine.begin() as conn:
            # Enable pgvector extension (P2 — multi-strategy retrieval)
            try:
                await conn.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))
            except Exception:
                # Extension unavailable — fall back to no-vector mode silently
                pass
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
            # P2: pgvector embedding column for semantic search over past decisions
            try:
                await conn.execute(sa.text(
                    "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS embedding vector(384)"
                ))
                # IVFFlat index for cosine similarity search
                await conn.execute(sa.text(
                    "CREATE INDEX IF NOT EXISTS decisions_embedding_cosine_idx "
                    "ON decisions USING ivfflat (embedding vector_cosine_ops) "
                    "WITH (lists = 50)"
                ))
                # Same column on history table — keeps schemas 1:1 (FE may want
                # semantic search over archived decisions later)
                await conn.execute(sa.text(
                    "ALTER TABLE decisions_history ADD COLUMN IF NOT EXISTS embedding vector(384)"
                ))
                await conn.execute(sa.text(
                    "CREATE INDEX IF NOT EXISTS decisions_history_embedding_cosine_idx "
                    "ON decisions_history USING ivfflat (embedding vector_cosine_ops) "
                    "WITH (lists = 50)"
                ))
            except Exception:
                # pgvector not installed — skip silently, multi-strategy will degrade gracefully
                pass

    async def close(self) -> None:
        if self._engine:
            await self._engine.dispose()

    async def save_decision(self, data: dict[str, Any]) -> None:
        """Dual-write to `decisions` (workspace) and `decisions_history` (audit).

        Both rows share the same primary key. `decisions` may be truncated by eval
        scripts; `decisions_history` is preserved across experiments for FE display.
        """
        if self._engine is None:
            return
        common_fields = dict(
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
        async with AsyncSession(self._engine) as session:
            session.add(DecisionRecord(**common_fields))
            session.add(DecisionHistoryRecord(**common_fields))
            await session.commit()

    async def write_embedding(self, decision_id: str, embedding: list[float]) -> bool:
        """Background hook: write embedding vector for a decision row.
        Updates BOTH `decisions` and `decisions_history` so FE-facing semantic
        search remains available even after the workspace table is truncated."""
        if self._engine is None or not embedding:
            return False
        vec_literal = "[" + ",".join(f"{x:.6f}" for x in embedding) + "]"
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    sa.text(
                        "UPDATE decisions SET embedding = CAST(:v AS vector) WHERE id = :id"
                    ),
                    {"v": vec_literal, "id": decision_id},
                )
                await conn.execute(
                    sa.text(
                        "UPDATE decisions_history SET embedding = CAST(:v AS vector) WHERE id = :id"
                    ),
                    {"v": vec_literal, "id": decision_id},
                )
            return True
        except Exception:
            return False

    async def search_similar_by_embedding(
        self,
        embedding: list[float],
        sid: int | None = None,
        mitre_technique: str | None = None,
        lookback_days: int = 90,
        limit: int = 5,
        min_similarity: float = 0.30,
    ) -> list[dict]:
        """Cosine similarity search over past decision embeddings.
        Returns list of dicts with similarity scores. Empty list on any error."""
        if self._engine is None or not embedding:
            return []
        vec_literal = "[" + ",".join(f"{x:.6f}" for x in embedding) + "]"
        from datetime import timedelta as _td
        cutoff = datetime.now(timezone.utc) - _td(days=lookback_days)
        # Use cosine distance (<=>); similarity = 1 - distance
        # Optional filters narrow result set when caller wants tighter match.
        filters = ["created_at >= :cutoff", "embedding IS NOT NULL"]
        params: dict[str, Any] = {
            "v": vec_literal,
            "cutoff": cutoff,
            "limit": limit,
            "min_sim": min_similarity,
        }
        if sid is not None:
            filters.append("alert_sid = :sid")
            params["sid"] = sid
        if mitre_technique:
            filters.append("mitre_technique = :mitre")
            params["mitre"] = mitre_technique
        sql = (
            "SELECT id, alert_sid, alert_src_ip, outcome, action, confidence, "
            "       mitre_technique, mitre_tactic, primary_hypothesis, created_at, "
            "       1 - (embedding <=> CAST(:v AS vector)) AS similarity "
            "FROM decisions "
            f"WHERE {' AND '.join(filters)} "
            "ORDER BY embedding <=> CAST(:v AS vector) ASC "
            "LIMIT :limit"
        )
        try:
            async with self._engine.connect() as conn:
                result = await conn.execute(sa.text(sql), params)
                rows = result.mappings().all()
            out: list[dict] = []
            for r in rows:
                sim = float(r.get("similarity") or 0.0)
                if sim < min_similarity:
                    continue
                out.append({
                    "id": r["id"],
                    "alert_sid": r["alert_sid"],
                    "alert_src_ip": r["alert_src_ip"],
                    "outcome": r["outcome"],
                    "action": r["action"],
                    "confidence": float(r["confidence"]) if r["confidence"] is not None else None,
                    "mitre_technique": r.get("mitre_technique"),
                    "mitre_tactic": r.get("mitre_tactic"),
                    "primary_hypothesis": r.get("primary_hypothesis"),
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                    "similarity": round(sim, 3),
                })
            return out
        except Exception:
            return []

    async def update_reasoning(
        self, decision_id: str, reasoning_data: dict[str, Any]
    ) -> bool:
        """Update an existing decision row with V3 reasoning trace fields.
        Updates BOTH `decisions` and `decisions_history`. Idempotent."""
        if self._engine is None:
            return False
        values = dict(
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
        async with AsyncSession(self._engine) as session:
            r1 = await session.execute(
                sa.update(DecisionRecord).where(DecisionRecord.id == decision_id).values(**values)
            )
            await session.execute(
                sa.update(DecisionHistoryRecord).where(DecisionHistoryRecord.id == decision_id).values(**values)
            )
            await session.commit()
            return r1.rowcount > 0

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

    # ── Read paths against decisions_history (FE display, never truncated) ─
    async def list_decisions_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Read full audit log from decisions_history table — used by FE.
        Survives eval runs because the workspace `decisions` table truncate
        does not touch this table."""
        if self._engine is None:
            return []
        async with AsyncSession(self._engine) as session:
            result = await session.execute(
                sa.select(DecisionHistoryRecord)
                .order_by(DecisionHistoryRecord.created_at.desc())
                .limit(limit)
            )
            rows = result.scalars().all()
            return [_record_to_dict(r) for r in rows]

    async def get_decision_history(self, decision_id: str) -> dict[str, Any] | None:
        """Fetch a single decision from history table — used by /decisions/{id} for FE modal."""
        if self._engine is None:
            return None
        async with AsyncSession(self._engine) as session:
            result = await session.execute(
                sa.select(DecisionHistoryRecord).where(DecisionHistoryRecord.id == decision_id)
            )
            r = result.scalar_one_or_none()
            return _record_to_dict(r) if r else None

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
