"""FlowWindow — fixed-size time window buffer for flow events.

Matches NetVigil paper window-based detection (NSDI'24, 2-min default).
Every `window_seconds` the buffer is snapshotted and handed to the
`on_window_close(flows, window_start, window_end)` callback. Buffer then
clears and accepts the next window's flows.

If the callback is slow (LLM batch dispatch), the next window starts on
schedule and the callback runs concurrently. Use a lock if back-pressure
needed.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Awaitable, Callable

import structlog

from ..models.flow import SuricataFlowEvent

log = structlog.get_logger()


WindowCallback = Callable[[list[SuricataFlowEvent], str, str], Awaitable[None]]


class FlowWindow:
    def __init__(
        self,
        window_seconds: int = 120,
        on_window_close: WindowCallback | None = None,
        max_buffer: int = 10_000,
    ) -> None:
        self._window_seconds = window_seconds
        self._on_window_close = on_window_close
        self._max_buffer = max_buffer
        self._buffer: list[SuricataFlowEvent] = []
        self._buffer_lock = asyncio.Lock()
        self._window_start_iso: str = ""
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._window_start_iso = _utc_now_iso()
        self._task = asyncio.create_task(self._loop())
        log.info("flow_window_started", window_seconds=self._window_seconds)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def push(self, flow: SuricataFlowEvent) -> None:
        async with self._buffer_lock:
            if len(self._buffer) >= self._max_buffer:
                # Drop oldest if overflow (preserves recent activity in window)
                self._buffer.pop(0)
            self._buffer.append(flow)

    async def buffer_size(self) -> int:
        async with self._buffer_lock:
            return len(self._buffer)

    async def _loop(self) -> None:
        try:
            while self._running:
                await asyncio.sleep(self._window_seconds)
                await self._fire()
        except asyncio.CancelledError:
            return

    async def _fire(self) -> None:
        """Snapshot buffer, hand off to callback, clear, advance window."""
        async with self._buffer_lock:
            snapshot = list(self._buffer)
            self._buffer.clear()
            window_start = self._window_start_iso
            window_end = _utc_now_iso()
            self._window_start_iso = window_end

        log.info(
            "flow_window_fire",
            flow_count=len(snapshot),
            window_start=window_start,
            window_end=window_end,
        )

        if self._on_window_close is None or not snapshot:
            return

        # Run callback concurrently — don't block next window
        try:
            await self._on_window_close(snapshot, window_start, window_end)
        except Exception as exc:
            log.error("flow_window_callback_error", error=str(exc))


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()
