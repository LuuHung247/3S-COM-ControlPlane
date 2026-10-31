"""PRIMARY enforcement backend: POST http://ids-agent:8766/rules.
ids-agent forces source=agent server-side, then forwards to Secure Framework."""
import asyncio

import httpx
import structlog

from ..models.decision import PolicyIntent
from ..models.enforcement import EnforcementResult
from .interface import EnforcementBackend

log = structlog.get_logger()


class IDSAgentProxyBackend(EnforcementBackend):
    ATTEMPTS = 3
    BACKOFF_S = 1.0

    def __init__(self, ids_agent_url: str, timeout: int = 10) -> None:
        self._base = ids_agent_url.rstrip("/")
        self._timeout = timeout

    async def enforce(self, intent: PolicyIntent) -> EnforcementResult:
        src = intent.src_ip if "/" in intent.src_ip else intent.src_ip + "/32"
        dst = intent.dst_ip if (intent.dst_ip and "/" in intent.dst_ip) else (intent.dst_ip + "/32" if intent.dst_ip else "")

        payload = {
            "rule_id": intent.rule_id,
            "action": intent.action.value,
            "src_ip": src,
            "priority": intent.priority,
            "comment": intent.comment,
            "ttl_seconds": intent.ttl_seconds,
        }
        if dst:
            payload["dst_ip"] = dst
        if intent.dst_port:
            payload["dst_port"] = intent.dst_port
        if intent.protocol:
            payload["protocol"] = intent.protocol

        # rule_id is a deterministic function of the flow tuple, so re-sending the same
        # rule is idempotent: transport faults and 5xx are retried a bounded number of
        # times before the decision is reported as an enforcement error.
        last_exc: Exception | None = None
        for attempt in range(self.ATTEMPTS):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(f"{self._base}/rules", json=payload)
                if resp.status_code >= 500 and attempt + 1 < self.ATTEMPTS:
                    log.warning("enforce_retry", rule_id=intent.rule_id, status=resp.status_code,
                                attempt=attempt + 1)
                    await asyncio.sleep(self.BACKOFF_S * (attempt + 1))
                    continue
                break
            except httpx.TransportError as exc:
                last_exc = exc
                log.warning("enforce_retry", rule_id=intent.rule_id, error=str(exc)[:120],
                            attempt=attempt + 1)
                await asyncio.sleep(self.BACKOFF_S * (attempt + 1))
        else:
            return EnforcementResult(success=False, backend="ids_agent_proxy",
                                     error=f"ids-agent unreachable after {self.ATTEMPTS} attempts: {last_exc}")
        try:
            data = resp.json() if resp.content else {}
            if resp.status_code < 400:
                log.info("enforced", rule_id=intent.rule_id, src_ip=src)
                return EnforcementResult(
                    success=True,
                    rule_id=intent.rule_id,
                    backend="ids_agent_proxy",
                    response=data,
                )
            return EnforcementResult(
                success=False,
                rule_id=intent.rule_id,
                backend="ids_agent_proxy",
                error=f"HTTP {resp.status_code}: {data}",
            )
        except Exception as exc:
            return EnforcementResult(
                success=False,
                backend="ids_agent_proxy",
                error=str(exc),
            )

    async def revoke(self, rule_id: str) -> EnforcementResult:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.delete(f"{self._base}/rules/{rule_id}")
                data = resp.json() if resp.content else {}
                return EnforcementResult(
                    success=resp.status_code < 400,
                    rule_id=rule_id,
                    backend="ids_agent_proxy",
                    response=data,
                    error="" if resp.status_code < 400 else f"HTTP {resp.status_code}",
                )
        except Exception as exc:
            return EnforcementResult(success=False, backend="ids_agent_proxy", error=str(exc))

    async def ping(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(f"{self._base}/health")
                return resp.status_code == 200
        except Exception:
            return False
