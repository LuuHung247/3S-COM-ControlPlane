"""ContextSnapshot: renders KG + active SF rules into a system prompt string."""
import asyncio
import time
from typing import Any

import httpx

from .topology import ZONES, HOSTS, LEAFS, ip_to_zone
from .policy import render_policy_matrix
from .knowledge import render_sid_knowledge


class ContextSnapshot:
    def __init__(self, ids_agent_url: str, refresh_interval: int = 30) -> None:
        self._ids_agent_url = ids_agent_url
        self._refresh_interval = refresh_interval
        self._active_rules: list[dict[str, Any]] = []
        self._last_refresh: float = 0.0
        self._lock = asyncio.Lock()

    async def refresh_rules(self) -> None:
        async with self._lock:
            if time.monotonic() - self._last_refresh < self._refresh_interval:
                return
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(f"{self._ids_agent_url}/rules")
                    if resp.status_code == 200:
                        data = resp.json()
                        # SF returns nested structure — flatten to a list
                        self._active_rules = _flatten_rules(data)
            except Exception:
                pass  # stale cache is fine
            self._last_refresh = time.monotonic()

    def render_for_prompt(self) -> str:
        parts: list[str] = []

        # Topology
        parts.append("=== NETWORK TOPOLOGY ===")
        for zone, attrs in ZONES.items():
            parts.append(f"Zone {zone}: CIDR={attrs['cidr']} LEAF={attrs['leaf']} SVI={attrs['svi']}")
        for host, attrs in HOSTS.items():
            parts.append(f"Host {host}: IP={attrs['ip']} Zone={attrs['zone']}")
        for leaf, attrs in LEAFS.items():
            parts.append(f"LEAF {leaf}: SSH={attrs['ssh_host']} Zones={attrs['zones']}")

        # Policy matrix
        parts.append("")
        parts.append("=== POLICY MATRIX ===")
        parts.append(render_policy_matrix())

        # SID knowledge
        parts.append("")
        parts.append("=== SURICATA SID KNOWLEDGE ===")
        parts.append(render_sid_knowledge())

        # Active agent rules (for idempotency awareness)
        parts.append("")
        parts.append("=== ACTIVE AGENT RULES (source=agent, from Secure Framework) ===")
        agent_rules = [r for r in self._active_rules if r.get("source") == "agent"]
        if agent_rules:
            for r in agent_rules:
                parts.append(
                    f"  rule_id={r.get('rule_id')} src={r.get('src_ip')} "
                    f"dst={r.get('dst_ip','')} action={r.get('action')} "
                    f"comment={r.get('comment','')}"
                )
        else:
            parts.append("  (none)")

        return "\n".join(parts)


def _flatten_rules(data: Any) -> list[dict]:
    """Normalize SF /api/rules response to a flat list of rule dicts."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        rules: list[dict] = []
        # SF returns {"success": true, "leaves": {"leaf-1": {"rules": {"notification": [...]}}}}
        leaves = data.get("leaves", {})
        for leaf_data in leaves.values():
            notifs = leaf_data.get("rules", {}).get("notification", [])
            for n in notifs:
                if isinstance(n, dict):
                    rules.append(n)
        return rules
    return []
