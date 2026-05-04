"""L5: Blast radius limits — per-minute, per-IP, and total agent rule caps."""
import asyncio
import time
from collections import defaultdict, deque


class RateLimiter:
    """
    Thread-safe (asyncio) rate limiter enforcing L5 blast radius constraints.
    All state is in-memory — resets on process restart. Postgres audit log is authoritative.
    """

    def __init__(
        self,
        max_per_minute: int = 5,
        max_total: int = 50,
        max_per_ip: int = 3,
        per_ip_window: int = 300,  # seconds
    ) -> None:
        self._max_per_minute = max_per_minute
        self._max_total = max_total
        self._max_per_ip = max_per_ip
        self._per_ip_window = per_ip_window

        self._lock = asyncio.Lock()
        self._minute_window: deque[float] = deque()
        self._total_count: int = 0
        self._per_ip: dict[str, deque[float]] = defaultdict(deque)

    async def check_and_consume(self, src_ip: str) -> str | None:
        """
        Check all blast radius limits. Returns error string if any limit exceeded,
        else consumes a slot and returns None.
        """
        async with self._lock:
            now = time.monotonic()

            # Evict old entries
            cutoff_min = now - 60
            while self._minute_window and self._minute_window[0] < cutoff_min:
                self._minute_window.popleft()

            bare_ip = src_ip.split("/")[0]
            cutoff_ip = now - self._per_ip_window
            while self._per_ip[bare_ip] and self._per_ip[bare_ip][0] < cutoff_ip:
                self._per_ip[bare_ip].popleft()

            # Check limits
            if len(self._minute_window) >= self._max_per_minute:
                return (
                    f"L5: Rate limit exceeded — {len(self._minute_window)} rules "
                    f"pushed in last 60s (max={self._max_per_minute})"
                )
            if self._total_count >= self._max_total:
                return (
                    f"L5: Total agent rule cap reached — {self._total_count} "
                    f"(max={self._max_total}). Manual review required."
                )
            if len(self._per_ip[bare_ip]) >= self._max_per_ip:
                return (
                    f"L5: Per-IP rate limit for {bare_ip} — "
                    f"{len(self._per_ip[bare_ip])} rules in {self._per_ip_window}s "
                    f"(max={self._max_per_ip})"
                )

            # Consume slot
            self._minute_window.append(now)
            self._total_count += 1
            self._per_ip[bare_ip].append(now)
            return None

    async def reset(self) -> None:
        """Clear all in-memory state (for eval/test resets between runs)."""
        async with self._lock:
            self._minute_window.clear()
            self._total_count = 0
            self._per_ip.clear()

    async def get_stats(self) -> dict:
        async with self._lock:
            return {
                "last_minute": len(self._minute_window),
                "total": self._total_count,
            }
