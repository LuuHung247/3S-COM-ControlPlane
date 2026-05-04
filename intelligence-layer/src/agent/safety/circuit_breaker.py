"""L8: Circuit breaker — halt agent enforcement after consecutive failures."""
import asyncio
import time


class CircuitBreaker:
    """
    Tracks consecutive enforcement failures.
    After fail_threshold consecutive failures, opens the circuit for halt_seconds.
    Failure counter resets on any successful enforcement.
    """

    def __init__(self, fail_threshold: int = 3, halt_seconds: int = 300) -> None:
        self._fail_threshold = fail_threshold
        self._halt_seconds = halt_seconds
        self._lock = asyncio.Lock()
        self._consecutive_failures: int = 0
        self._open_until: float = 0.0

    async def is_open(self) -> tuple[bool, str]:
        """Return (is_open, reason). If open, enforcement must not proceed."""
        async with self._lock:
            if self._open_until > time.monotonic():
                remaining = int(self._open_until - time.monotonic())
                return True, (
                    f"L8: Circuit breaker OPEN — {self._consecutive_failures} consecutive "
                    f"failures. Halted for {remaining}s more."
                )
            return False, ""

    async def record_success(self) -> None:
        async with self._lock:
            self._consecutive_failures = 0
            self._open_until = 0.0

    async def record_failure(self) -> None:
        async with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._fail_threshold:
                self._open_until = time.monotonic() + self._halt_seconds

    async def get_stats(self) -> dict:
        async with self._lock:
            return {
                "consecutive_failures": self._consecutive_failures,
                "is_open": self._open_until > time.monotonic(),
                "open_until": self._open_until,
            }
