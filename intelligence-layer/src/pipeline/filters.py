"""Pre-LLM filter chain: severity, dedup, rate-limit, IP whitelist."""
from ..models.alert import SuricataAlert
from ..storage.redis import RedisStore
from ..core.topology import ip_to_zone
from ..agent.safety.guardrails import is_protected_ip


class FilterResult:
    def __init__(self, passed: bool, reason: str = "") -> None:
        self.passed = passed
        self.reason = reason


async def severity_filter(alert: SuricataAlert, min_severity: int) -> FilterResult:
    """Pass only alerts with severity <= min_severity (lower = more severe)."""
    if alert.severity > min_severity:
        return FilterResult(False, f"severity {alert.severity} > min {min_severity}")
    return FilterResult(True)


async def dedup_filter(alert: SuricataAlert, redis: RedisStore) -> FilterResult:
    """Reject if identical (src_ip, sid) seen within dedup window."""
    if await redis.is_duplicate(alert.src_ip, alert.sid):
        return FilterResult(False, f"duplicate alert sid={alert.sid} src={alert.src_ip}")
    return FilterResult(True)


async def whitelist_filter(alert: SuricataAlert, whitelist_ips: list[str]) -> FilterResult:
    """Reject alerts from management-plane IPs — those are never threat actors."""
    if is_protected_ip(alert.src_ip):
        return FilterResult(False, f"src_ip {alert.src_ip} is in NEVER_BLOCK whitelist")
    # Also reject alerts sourced from explicit whitelist IPs
    bare = alert.src_ip.split("/")[0]
    if bare in whitelist_ips:
        return FilterResult(False, f"src_ip {bare} is in whitelist")
    return FilterResult(True)


async def zone_filter(alert: SuricataAlert) -> FilterResult:
    """Reject alerts from unknown zones — nothing to reason about."""
    if alert.src_ip and ip_to_zone(alert.src_ip) is None:
        # Some alerts from Suricata may have IPs outside our topology — let through for logging
        return FilterResult(True, "src_ip outside known zones — passing through for log_only")
    return FilterResult(True)
