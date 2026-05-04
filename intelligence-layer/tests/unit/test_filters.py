"""Unit tests for pipeline filter chain."""
import pytest
from unittest.mock import AsyncMock

from src.models.alert import SuricataAlert
from src.pipeline.filters import severity_filter, dedup_filter, whitelist_filter


def _make_alert(src_ip="10.1.100.10", sid=9000001, severity=1) -> SuricataAlert:
    return SuricataAlert(
        src_ip=src_ip,
        dest_ip="10.1.200.10",
        alert={"signature_id": sid, "severity": severity, "signature": "test", "category": "test"},
    )


@pytest.mark.asyncio
async def test_severity_filter_passes_p1():
    alert = _make_alert(severity=1)
    result = await severity_filter(alert, min_severity=2)
    assert result.passed

@pytest.mark.asyncio
async def test_severity_filter_blocks_p3():
    alert = _make_alert(severity=3)
    result = await severity_filter(alert, min_severity=2)
    assert not result.passed

@pytest.mark.asyncio
async def test_dedup_filter_passes_first():
    alert = _make_alert()
    redis = AsyncMock()
    redis.is_duplicate = AsyncMock(return_value=False)
    result = await dedup_filter(alert, redis)
    assert result.passed

@pytest.mark.asyncio
async def test_dedup_filter_blocks_duplicate():
    alert = _make_alert()
    redis = AsyncMock()
    redis.is_duplicate = AsyncMock(return_value=True)
    result = await dedup_filter(alert, redis)
    assert not result.passed

@pytest.mark.asyncio
async def test_whitelist_filter_blocks_mgmt_ip():
    alert = _make_alert(src_ip="10.10.6.238")
    result = await whitelist_filter(alert, whitelist_ips=[])
    assert not result.passed

@pytest.mark.asyncio
async def test_whitelist_filter_passes_host_ip():
    alert = _make_alert(src_ip="10.1.100.10")
    result = await whitelist_filter(alert, whitelist_ips=[])
    assert result.passed
