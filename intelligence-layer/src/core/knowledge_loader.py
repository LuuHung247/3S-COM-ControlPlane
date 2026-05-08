"""KnowledgeLoader — tiered caching for LLM agent context injection.

3-tier model:
  Tier 1 STATIC: system model + threat playbook + enforcement contract + invariants.
                 Loaded once at container startup. Never refreshes.
  Tier 2 SEMI-DYNAMIC: active SF rules + baselines render. Refreshes every N seconds.
  Tier 3 PER-ALERT: alert-specific context (asset profiles for src/dst, baseline match,
                    recent alert summary). Constructed per request.

This replaces the old ContextSnapshot which re-rendered everything per alert.
"""
import asyncio
import time
from typing import Any

import httpx
import structlog

from . import system_model
from . import baselines
from . import threat_playbook
from . import enforcement_plane
from . import invariants

log = structlog.get_logger()


class KnowledgeLoader:
    """Tiered knowledge cache. Single instance per container lifetime."""

    def __init__(self, ids_agent_url: str, semi_dynamic_ttl: int = 30) -> None:
        self._ids_agent_url = ids_agent_url
        self._semi_dynamic_ttl = semi_dynamic_ttl

        # Tier 1 — static, computed once
        self._tier1_cached: str | None = None

        # Tier 2 — semi-dynamic, TTL-based
        self._tier2_cached: str | None = None
        self._tier2_loaded_at: float = 0.0
        self._tier2_lock = asyncio.Lock()
        self._active_rules: list[dict[str, Any]] = []

    # ── Tier 1: static core ──────────────────────────────────────────────────
    def render_static_core(self) -> str:
        """FULL knowledge dump — used for startup verification, KG endpoint, debugging.
        Per-alert use case should call build_alert_specific_prompt() instead (smaller).
        """
        if self._tier1_cached is None:
            parts = [
                "# DATACENTER ZERO TRUST OPERATIONS RUNBOOK",
                "",
                "You are the AI security agent for this datacenter. The following knowledge "
                "base describes the production system you operate. Treat it as authoritative.",
                "",
                system_model.render_for_prompt(),
                "",
                baselines.render_for_prompt(),
                "",
                threat_playbook.render_for_prompt(),
                "",
                enforcement_plane.render_for_prompt(),
                "",
                invariants.render_for_prompt(),
            ]
            self._tier1_cached = "\n".join(parts)
            log.info("knowledge_tier1_loaded", token_estimate=len(self._tier1_cached) // 4)
        return self._tier1_cached

    def render_alert_scoped_core(
        self, sid: int, src_ip: str = "", dst_ip: str = ""
    ) -> str:
        """Tier 1 alert-conditioned: render ONLY zones/assets/SIDs/baselines relevant
        to THIS alert. Cuts prompt size ~52% vs render_static_core().

        Always includes: invariants + enforcement summary (mandatory hard constraints).
        Conditional: zones+assets involved, this SID's detail + matching kill chains,
        baselines involving these IPs.
        """
        parts = [
            "# DATACENTER ZERO TRUST OPERATIONS RUNBOOK (alert-scoped)",
            "",
            "You are the AI security agent. The runbook below describes the slice of "
            "production knowledge most relevant to this specific alert.",
            "",
            system_model.render_for_alert(src_ip, dst_ip),
            "",
            baselines.render_for_alert(src_ip, dst_ip),
            "",
            threat_playbook.render_for_alert(sid),
            "",
            enforcement_plane.render_summary(),
            "",
            invariants.render_for_prompt(),
        ]
        return "\n".join(parts)

    # ── Tier 2: semi-dynamic (active SF rules) ──────────────────────────────
    async def refresh_semi_dynamic(self, force: bool = False) -> None:
        """Refresh active SF rules from /rules endpoint. Cached for TTL seconds."""
        async with self._tier2_lock:
            now = time.monotonic()
            if not force and (now - self._tier2_loaded_at) < self._semi_dynamic_ttl:
                return
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(f"{self._ids_agent_url}/rules")
                    if resp.status_code == 200:
                        self._active_rules = _flatten_rules(resp.json())
            except Exception as exc:
                log.warning("knowledge_tier2_refresh_failed", error=str(exc))
                # keep stale cache
            self._tier2_cached = self._render_semi_dynamic_text()
            self._tier2_loaded_at = now

    def _render_semi_dynamic_text(self) -> str:
        agent_rules = [r for r in self._active_rules if r.get("source") == "agent"]
        if not agent_rules:
            rules_section = "(no agent-managed rules currently active)"
        else:
            lines = []
            for r in agent_rules:
                src = r.get("src-prefix") or r.get("src_ip") or r.get("src-ip") or ""
                dst = r.get("dst-prefix") or r.get("dst_ip") or r.get("dst-ip") or ""
                rid = r.get("rule-id") or r.get("rule_id") or ""
                action = r.get("action", "")
                lines.append(f"  - {rid}: {action} src={src} dst={dst}")
            rules_section = "\n".join(lines)

        return (
            "## ACTIVE AGENT-MANAGED RULES (live from Secure Framework)\n\n"
            f"{rules_section}\n\n"
            "Use this to detect idempotency — if a rule with same src/dst/port already exists, "
            "POST same rule_id to refresh TTL rather than creating a duplicate."
        )

    def render_semi_dynamic(self) -> str:
        """Returns cached text. Call refresh_semi_dynamic() before to ensure freshness."""
        return self._tier2_cached or "(active rules cache not yet populated)"

    # ── Tier 3: per-alert context ────────────────────────────────────────────
    def render_alert_context(
        self,
        src_ip: str,
        dst_ip: str = "",
        dst_port: int = 0,
        proto: str = "tcp",
        alert_history_summary: dict | None = None,
        investigation: dict | None = None,
        reputation: Any = None,
    ) -> str:
        """Per-alert micro-context — only what's relevant for this specific alert.

        If `investigation` dict is provided (from tools.prefetch_investigation_context),
        renders structured tool output sections.
        """
        parts = ["## ALERT-SPECIFIC CONTEXT\n"]

        # Source asset profile
        src_asset = system_model.get_asset(src_ip)
        if src_asset:
            parts.append(
                f"### Source: {src_asset.hostname} ({src_asset.ip}, zone {src_asset.zone}, "
                f"{src_asset.tier})\n"
                f"- Role: {src_asset.role}\n"
                f"- Criticality: {src_asset.criticality.value}\n"
                f"- If blocked: {src_asset.if_blocked_impact}\n"
                f"- If compromised: {src_asset.if_compromised_impact}"
            )
        else:
            parts.append(f"### Source: {src_ip} (UNKNOWN — not in asset inventory)")

        # Destination asset profile
        if dst_ip:
            dst_asset = system_model.get_asset(dst_ip)
            if dst_asset:
                parts.append(
                    f"\n### Destination: {dst_asset.hostname} ({dst_asset.ip}, zone {dst_asset.zone})\n"
                    f"- Role: {dst_asset.role}\n"
                    f"- Criticality: {dst_asset.criticality.value}"
                )

        # Baseline match — is this flow legitimate production traffic?
        if dst_ip and dst_port:
            match = baselines.match_baseline(src_ip, dst_ip, dst_port, proto)
            if match:
                parts.append(
                    f"\n### ⚠ BASELINE MATCH: this flow matches known production pattern '{match.name}'\n"
                    f"- {match.production_description}\n"
                    f"- Cadence: {match.cadence}, criticality={match.criticality_to_business.value}\n"
                    f"- This is LEGITIMATE traffic. Strong evidence against blocking unless other indicators (rate burst, off-pattern timing) suggest abuse."
                )
            else:
                parts.append(
                    "\n### Baseline match: NONE — flow is NOT in known production traffic patterns."
                )

        # Recent activity (aggregated summary)
        if alert_history_summary:
            parts.append(
                f"\n### Recent activity from {src_ip} (last 30 days)\n"
                f"- Total alerts: {alert_history_summary.get('total_alerts', 0)}\n"
                f"- Distinct SIDs: {alert_history_summary.get('distinct_sids', 0)}\n"
                f"- Trust score: {alert_history_summary.get('trust_score')}\n"
                f"- Past decisions: {alert_history_summary.get('decision_summary', '(none)')}"
            )

        # Runtime asset reputation — short-window behavioral score (closes learning loop)
        if reputation is not None:
            from .asset_reputation import render_for_prompt as _render_rep, AssetReputation
            if isinstance(reputation, AssetReputation):
                parts.append("\n" + _render_rep(reputation))

        # Investigation tool outputs (NEW — Phase 1)
        if investigation:
            parts.append("\n## INVESTIGATION FINDINGS (pre-fetched, structured)\n")

            # Tool 1: blast radius
            neighbors = investigation.get("asset_neighbors", {})
            if neighbors and not neighbors.get("error"):
                parts.append("### Blast radius assessment (if we block source)")
                parts.append(f"- Asset known: {neighbors.get('asset_known')}, criticality={neighbors.get('criticality')}")
                parts.append(f"- Blast radius score: **{neighbors.get('blast_radius_score')}**")
                outbound = neighbors.get("outbound_flows", [])
                inbound = neighbors.get("inbound_flows", [])
                if outbound:
                    flows_str = ", ".join(f"{f['name']}({f['criticality']})" for f in outbound)
                    parts.append(f"- Outbound flows from this IP: {flows_str}")
                if inbound:
                    parts.append(f"- Inbound flows to this IP: {len(inbound)} flows")
                if neighbors.get("if_blocked"):
                    parts.append(f"- If blocked: {neighbors.get('if_blocked')}")

            # Tool 2: past incidents — multi-strategy (P2)
            past = investigation.get("past_incidents", {})
            if past and not past.get("error"):
                parts.append("\n### Past similar incidents — multi-strategy retrieval (90-day lookback)")
                exact_n = past.get("match_count", 0)
                semantic_n = past.get("semantic_match_count", 0)
                mitre_n = past.get("mitre_match_count", 0)
                if exact_n + semantic_n + mitre_n == 0:
                    parts.append(f"- {past.get('note', 'No history')}")
                else:
                    parts.append(
                        f"- Strategy hits — exact_SID: {exact_n}, semantic: {semantic_n}, "
                        f"mitre_technique: {mitre_n}"
                    )
                    parts.append(f"- Pattern: {past.get('pattern_assessment')}")
                    # KEEP top-3 across all 3 retrieval strategies. Reasoning quality
                    # is the point of memory; trimming to save tokens hurts the most
                    # valuable paths (semantic + MITRE) which catch novel attack
                    # variants where exact-SID returns zero. In production, attacks
                    # are almost never identical to past incidents — semantic and
                    # MITRE retrievals are precisely what makes memory worth having.
                    if exact_n > 0:
                        parts.append(f"- Outcome breakdown (exact-SID): {past.get('outcome_breakdown')}")
                        last = past.get("last_decisions", [])[:3]
                        if last:
                            last_str = "; ".join(
                                f"[{d['date'][:10]}] {d['outcome']} action={d['action']} conf={d['confidence']}"
                                for d in last
                            )
                            parts.append(f"- Recent exact-SID decisions: {last_str}")
                    if semantic_n > 0:
                        sem_str = "; ".join(
                            f"SID {m['alert_sid']} sim={m['similarity']:.2f} {m['outcome']}"
                            for m in past.get("semantic_matches", [])[:3]
                        )
                        parts.append(f"- Semantic-similar (vector cosine): {sem_str}")
                    if mitre_n > 0:
                        mt_str = "; ".join(
                            f"SID {m['alert_sid']} {m['outcome']} action={m['action']}"
                            for m in past.get("mitre_matches", [])[:3]
                        )
                        parts.append(f"- Same MITRE technique, different SID: {mt_str}")

            # Tool 3: block impact simulation
            impact = investigation.get("block_impact", {})
            if impact and not impact.get("error"):
                parts.append("\n### Block impact simulation (counterfactual)")
                full = impact.get("full_block_impact", {})
                targeted = impact.get("targeted_block_impact", {})
                if full.get("outbound_flows_broken"):
                    parts.append("- Full-source block would break:")
                    for f in full["outbound_flows_broken"]:
                        parts.append(f"  - {f['name']} (criticality={f['criticality']}): {f['consequence']}")
                if targeted.get("rule_form") and "(no dst" not in targeted["rule_form"]:
                    parts.append(f"- Targeted block ({targeted['rule_form']}): "
                                 f"matches baseline={targeted.get('matches_legitimate_baseline')}")
                parts.append(f"- Recommendation: {impact.get('recommendation')}")

            # Kill chain match
            kc_match = investigation.get("kill_chain_match", [])
            if kc_match:
                parts.append("\n### Kill-chain stage matches")
                for m in kc_match:
                    parts.append(
                        f"- **{m['kill_chain']}** stage {m['stage']} ({m['tactic']}): {m['indicator']}"
                    )
                    parts.append(f"  - Recommended intervention: {m['intervention_point']}")
                    parts.append(f"  - Containment: {m['containment_strategy']}")

        return "\n".join(parts)

    # ── Composite: full system prompt ────────────────────────────────────────
    async def build_system_prompt(self) -> str:
        """Legacy full-knowledge system prompt. Use build_alert_specific_prompt for
        per-alert path."""
        await self.refresh_semi_dynamic()
        return f"{self.render_static_core()}\n\n{self.render_semi_dynamic()}"

    async def build_alert_specific_prompt(
        self, sid: int, src_ip: str = "", dst_ip: str = ""
    ) -> str:
        """Composite per-alert system prompt: alert-scoped Tier 1 + Tier 2 active rules.
        Significantly smaller than build_system_prompt() — typical 3K vs 6.3K tokens.
        """
        await self.refresh_semi_dynamic()
        return (
            f"{self.render_alert_scoped_core(sid, src_ip, dst_ip)}\n\n"
            f"{self.render_semi_dynamic()}"
        )


def _flatten_rules(data: Any) -> list[dict]:
    """Normalize SF /api/rules response to a flat list of rule dicts."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        rules: list[dict] = []
        leaves = data.get("leaves", {})
        for leaf_data in leaves.values():
            if isinstance(leaf_data, dict):
                # ids-agent proxy returns gNMI notification format
                notifs = (leaf_data.get("rules") or {}).get("notification", [])
                for n in notifs:
                    if not isinstance(n, dict):
                        continue
                    for upd in n.get("update", []):
                        val = upd.get("val", {})
                        if isinstance(val, dict) and val:
                            rules.append(val)
        return rules
    return []
