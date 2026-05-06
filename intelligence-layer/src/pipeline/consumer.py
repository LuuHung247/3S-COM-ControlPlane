"""SSE consumer: subscribe to ids-agent /events, parse alerts, feed pipeline.

Also mirrors all alert + flow events to EventsStore (Redis DB 1) so the frontend
Monitor page can hydrate from server-side buffer instead of Suricata's transient
3-min window.
"""
import asyncio
import json
import structlog

import httpx

from ..models.alert import SuricataAlert
from ..storage.events_store import EventsStore

log = structlog.get_logger()

_HANDSHAKE_TYPES = {"connected", "heartbeat"}


class SSEConsumer:
    def __init__(
        self,
        ids_agent_url: str,
        on_alert,  # Callable[[SuricataAlert], Awaitable[None]]
        events_store: EventsStore | None = None,
        flow_poll_interval: float = 5.0,
        reconnect_delay_base: float = 3.0,
        reconnect_delay_max: float = 60.0,
    ) -> None:
        self._base_url = ids_agent_url
        self._url = f"{ids_agent_url}/events"
        self._flows_url = f"{ids_agent_url}/flows"
        self._on_alert = on_alert
        self._events_store = events_store
        self._flow_poll_interval = flow_poll_interval
        self._flow_poll_seen: set[str] = set()  # de-dup ring of recent flow keys
        self._reconnect_delay_base = reconnect_delay_base
        self._reconnect_delay_max = reconnect_delay_max
        self._running = False
        self._task: asyncio.Task | None = None
        self._flow_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        if self._events_store is not None:
            self._flow_task = asyncio.create_task(self._flow_poll_loop())

    async def stop(self) -> None:
        self._running = False
        for task in (self._task, self._flow_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    async def _run_loop(self) -> None:
        delay = self._reconnect_delay_base
        while self._running:
            try:
                await self._consume()
                delay = self._reconnect_delay_base
            except asyncio.CancelledError:
                return
            except Exception as exc:
                log.warning("sse_disconnected", error=str(exc), retry_in=delay)
            if self._running:
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._reconnect_delay_max)

    async def _consume(self) -> None:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", self._url) as resp:
                resp.raise_for_status()
                log.info("sse_connected", url=self._url)
                async for line in resp.aiter_lines():
                    if not self._running:
                        return
                    if not line.startswith("data: "):
                        continue
                    payload = line[6:].strip()
                    if not payload:
                        continue
                    try:
                        data = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    # Skip handshake messages
                    if data.get("type") in _HANDSHAKE_TYPES:
                        continue

                    # Mirror flow events to EventsStore (no agent dispatch)
                    if data.get("event_type") == "flow":
                        if self._events_store is not None:
                            try:
                                await self._events_store.push_flow(data)
                            except Exception as exc:
                                log.warning("events_store_push_flow_failed", error=str(exc))
                        continue

                    if "alert" not in data or "src_ip" not in data:
                        continue

                    # Mirror alert to EventsStore for frontend buffer
                    if self._events_store is not None:
                        try:
                            await self._events_store.push_violation(data)
                        except Exception as exc:
                            log.warning("events_store_push_violation_failed", error=str(exc))

                    alert = SuricataAlert.from_raw(data)
                    try:
                        await self._on_alert(alert)
                    except Exception as exc:
                        log.error("on_alert_error", error=str(exc))

    async def _flow_poll_loop(self) -> None:
        """Fallback flow ingestion: poll ids-agent /flows endpoint and ingest new flows.
        ids-agent /events SSE may not always include flow records; this poller catches
        any flow that bypassed the SSE channel."""
        while self._running:
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(self._flows_url, params={"last": 100})
                    if resp.status_code == 200:
                        flows = resp.json()
                        if isinstance(flows, list):
                            await self._ingest_flow_batch(flows)
            except Exception as exc:
                log.debug("flow_poll_failed", error=str(exc))

            try:
                await asyncio.sleep(self._flow_poll_interval)
            except asyncio.CancelledError:
                return

    async def _ingest_flow_batch(self, flows: list) -> None:
        if self._events_store is None:
            return
        for f in flows:
            if not isinstance(f, dict):
                continue
            # Dedup key: timestamp + src + dst + ports
            k = (
                f"{f.get('timestamp','')}|{f.get('src_ip','')}|"
                f"{f.get('src_port','')}|{f.get('dest_ip','')}|"
                f"{f.get('dest_port','')}"
            )
            if k in self._flow_poll_seen:
                continue
            self._flow_poll_seen.add(k)
            # Bound dedup ring to last 500 flow keys
            if len(self._flow_poll_seen) > 500:
                # Drop ~half (Python set has no FIFO; arbitrary drop is acceptable)
                self._flow_poll_seen = set(list(self._flow_poll_seen)[-250:])
            try:
                await self._events_store.push_flow(f)
            except Exception as exc:
                log.warning("events_store_push_flow_failed", error=str(exc))
