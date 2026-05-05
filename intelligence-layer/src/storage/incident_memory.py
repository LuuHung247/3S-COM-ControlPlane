"""IncidentMemory — retrospective labeling for past decisions.

Background coroutine: after a rule expires (or N hours after enforce), check whether
the same src_ip has fired alerts again. If no recurrence within window → label
true_positive (block was effective). Otherwise label recurrence/false_positive.

This gives the agent learned context: 'past decisions for this IP/SID had X true positives,
Y false positives' — feeds into get_ip_summary() and improves future reasoning.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from .postgres import DecisionRecord, PostgresStore
from ..observability.langfuse_tracer import get_global_tracer

log = structlog.get_logger()


# Map retrospective outcome to numeric score (Langfuse evaluates over time)
_RETROSPECTIVE_SCORE = {
    "true_positive": 1.0,
    "recurrence": 0.3,
    "false_positive": 0.0,
    "inconclusive": 0.5,
}


class IncidentLabeler:
    """Periodic task: scan unlabeled decisions, query IDS for recurrence, write label."""

    def __init__(
        self,
        postgres: PostgresStore,
        ids_agent_url: str,
        scan_interval_seconds: int = 300,           # every 5 min
        label_age_minutes: int = 30,                # only label decisions older than this
        recurrence_lookahead_minutes: int = 60,     # after enforce, watch this window
    ) -> None:
        self._pg = postgres
        self._ids_url = ids_agent_url
        self._scan_interval = scan_interval_seconds
        self._label_age_min = label_age_minutes
        self._lookahead_min = recurrence_lookahead_minutes
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run_loop())
        log.info("incident_labeler_started", interval=self._scan_interval)

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
            self._task = None

    async def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                labeled = await self._label_pending()
                if labeled > 0:
                    log.info("incident_labeler_cycle_done", labeled=labeled)
            except Exception as exc:
                log.warning("incident_labeler_error", error=str(exc))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._scan_interval)
            except asyncio.TimeoutError:
                continue

    async def _label_pending(self) -> int:
        """Scan unlabeled enforced decisions older than label_age_min and label them."""
        if self._pg._engine is None:
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self._label_age_min)

        async with async_sessionmaker(self._pg._engine, expire_on_commit=False)() as sess:
            q = await sess.execute(
                select(DecisionRecord)
                .where(
                    DecisionRecord.outcome == "enforced",
                    DecisionRecord.retrospective_outcome.is_(None),
                    DecisionRecord.created_at <= cutoff,
                )
                .limit(20)   # batch limit per cycle
            )
            decisions = q.scalars().all()

            if not decisions:
                return 0

            labeled = 0
            tracer = get_global_tracer()
            for d in decisions:
                label, notes = await self._label_one(d)
                await sess.execute(
                    update(DecisionRecord)
                    .where(DecisionRecord.id == d.id)
                    .values(
                        retrospective_outcome=label,
                        retrospective_notes=notes,
                        labeled_at=datetime.now(timezone.utc),
                    )
                )
                # Push score to Langfuse trace if linked — enables quality dashboards
                if tracer is not None and tracer.enabled and d.trace_id:
                    score_val = _RETROSPECTIVE_SCORE.get(label, 0.5)
                    tracer.score_trace(
                        trace_id=d.trace_id,
                        name="retrospective_outcome",
                        value=score_val,
                        comment=f"{label}: {notes[:200]}",
                    )
                labeled += 1
            await sess.commit()
            return labeled

    async def _label_one(self, decision: DecisionRecord) -> tuple[str, str]:
        """Decide label by querying IDS for alerts after the decision was made.

        Logic:
        - Window = [decision.created_at, decision.created_at + lookahead]
        - Query IDS alerts since decision time, filter by src_ip
        - If 0 recurrence → true_positive (rule worked)
        - If recurrence within TTL → could mean rule didn't take effect or attacker pivoted
        - If recurrence after TTL expired → expected (block lifted)
        """
        if decision.alert_src_ip is None:
            return ("inconclusive", "missing alert_src_ip")

        since = decision.created_at.isoformat()
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    f"{self._ids_url}/alerts",
                    params={"since": since, "last": 200},
                )
                if resp.status_code != 200:
                    return ("inconclusive", f"IDS API status {resp.status_code}")
                payload = resp.json()
        except Exception as exc:
            return ("inconclusive", f"IDS query failed: {exc}")

        alerts = payload.get("alerts", []) if isinstance(payload, dict) else payload
        if not isinstance(alerts, list):
            return ("inconclusive", "unexpected IDS payload")

        # Count recurrences from same src_ip
        recurrences = []
        for a in alerts:
            a_src = a.get("src_ip")
            if a_src == decision.alert_src_ip:
                recurrences.append(a)

        ttl = decision.ttl_seconds or 3600
        ttl_end = decision.created_at + timedelta(seconds=ttl)

        within_ttl = []
        after_ttl = []
        for a in recurrences:
            ts_str = a.get("timestamp")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                continue
            if ts < ttl_end:
                within_ttl.append(a)
            else:
                after_ttl.append(a)

        if not recurrences:
            return ("true_positive",
                    f"No recurrence from {decision.alert_src_ip} in lookahead window. Block effective.")

        if within_ttl:
            return ("recurrence",
                    f"{len(within_ttl)} alerts during active TTL — rule may have been bypassed or attacker persisted")

        return ("true_positive",
                f"Recurrence only after TTL expired ({len(after_ttl)} events). Block was effective during active period.")
