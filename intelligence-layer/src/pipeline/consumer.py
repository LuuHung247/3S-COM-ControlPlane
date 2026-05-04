"""SSE consumer: subscribe to ids-agent /events, parse alerts, feed pipeline."""
import asyncio
import json
import structlog

import httpx

from ..models.alert import SuricataAlert

log = structlog.get_logger()

_HANDSHAKE_TYPES = {"connected", "heartbeat"}


class SSEConsumer:
    def __init__(
        self,
        ids_agent_url: str,
        on_alert,  # Callable[[SuricataAlert], Awaitable[None]]
        reconnect_delay_base: float = 3.0,
        reconnect_delay_max: float = 60.0,
    ) -> None:
        self._url = f"{ids_agent_url}/events"
        self._on_alert = on_alert
        self._reconnect_delay_base = reconnect_delay_base
        self._reconnect_delay_max = reconnect_delay_max
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
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
                    if "alert" not in data or "src_ip" not in data:
                        continue
                    alert = SuricataAlert.from_raw(data)
                    try:
                        await self._on_alert(alert)
                    except Exception as exc:
                        log.error("on_alert_error", error=str(exc))
