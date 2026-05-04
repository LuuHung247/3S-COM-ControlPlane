"""Gate: orchestrate filter chain → bool. Alert passes only when all filters pass."""
import structlog

from ..models.alert import SuricataAlert
from ..storage.redis import RedisStore
from .filters import severity_filter, dedup_filter, whitelist_filter, zone_filter

log = structlog.get_logger()


class AlertGate:
    def __init__(
        self,
        redis: RedisStore,
        min_severity: int = 2,
        whitelist_ips: list[str] | None = None,
    ) -> None:
        self._redis = redis
        self._min_severity = min_severity
        self._whitelist_ips = whitelist_ips or []

    async def should_process(self, alert: SuricataAlert) -> tuple[bool, str]:
        """
        Run all filters in order. Return (should_process, reason).
        First failure short-circuits the chain.
        """
        # Create coroutines lazily to avoid "never awaited" warnings on early return
        for make_check in [
            lambda: severity_filter(alert, self._min_severity),
            lambda: dedup_filter(alert, self._redis),
            lambda: whitelist_filter(alert, self._whitelist_ips),
            lambda: zone_filter(alert),
        ]:
            result = await make_check()
            if not result.passed:
                log.info(
                    "alert_filtered",
                    sid=alert.sid,
                    src_ip=alert.src_ip,
                    reason=result.reason,
                )
                return False, result.reason

        return True, ""
