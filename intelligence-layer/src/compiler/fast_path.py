"""Runtime use of a compiled response program.

The program answers an alert before any model call. It is used only while all of the
following hold, and the agent falls back to the full runtime pipeline otherwise:
  - the artefact was verified when compiled,
  - it was compiled from exactly the knowledge base the service is running on
    (snapshot digest match), so a stale program is never applied after a KB change,
  - it passes exhaustive verification again when loaded, in this process.
A decision the program makes still goes through the runtime validators, confidence
gate, rate limiter, circuit breaker and Secure Framework, like any other decision.
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from ..agent.safety.guardrails import is_protected_ip
from ..models.decision import PolicyAction, PolicyIntent
from .dsl import Ensemble, Features, Outcome, Program
from .kb import KBSnapshot
from .verifier import verify

log = structlog.get_logger()

HISTORY_WINDOW_S = 600


def _ts(alert: dict) -> float | None:
    raw = alert.get("timestamp")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def extract_features(kb: KBSnapshot, alert, history: list[dict]) -> Features:
    """Map an alert and the source's recent alert history onto the program's inputs.
    History entries older than HISTORY_WINDOW_S (by alert timestamp) are ignored."""
    src, dst = alert.src_ip, alert.dest_ip
    sz, dz = kb.zone_of(src), kb.zone_of(dst)
    now = _ts(alert.raw) or time.time()
    recent = [h for h in history if (t := _ts(h)) is None or 0 <= now - t <= HISTORY_WINDOW_S]
    others = {h.get("dest_ip") for h in recent} - {dst, None}
    ports = {int(h.get("dest_port") or 0) for h in recent if h.get("dest_ip") == dst}
    ports.discard(int(alert.dest_port or 0))
    return Features(
        sid=alert.sid if alert.sid in kb.sids else 0,
        # P1..P4 only; anything else maps to P4, the least severe, which never enforces.
        severity=int(alert.severity) if 1 <= int(alert.severity or 0) <= 4 else 4,
        src_zone=sz, dst_zone=dz, verdict=kb.verdict(sz, dz),
        src_protected=kb.is_protected(src) or is_protected_ip(src),
        prior_alerts=1 if recent else 0,
        distinct_targets=min(len(others), 2),
        ports_on_target=1 if ports else 0)


class CompiledPolicy:
    def __init__(self) -> None:
        self.status = "not loaded"
        self.path = ""
        self.kb_digest = ""
        self.artifact: dict[str, Any] = {}
        self._decider: Program | Ensemble | None = None
        self._kb: KBSnapshot | None = None
        self.enabled = False
        self.stats = {"decided": 0, "abstained": 0}

    @property
    def active(self) -> bool:
        return self.enabled and self.status == "active" and self._decider is not None

    def describe(self) -> dict:
        return {"enabled": self.enabled, "status": self.status, "path": self.path,
                "kb_digest": self.kb_digest, "model": self.artifact.get("model"),
                "compiled_at": self.artifact.get("compiled_at"),
                "members": len(self.artifact.get("ensemble") or []) or (1 if self.artifact.get("program") else 0),
                **self.stats}

    async def load(self, path: str, kb_dir: str, enabled: bool = True) -> None:
        """Load and re-verify off the event loop; activates only on success."""
        self.enabled, self.path, self.status = enabled, path, "verifying"
        self._decider = None
        try:
            art = json.loads(Path(path).read_text())
            kb = KBSnapshot.load(kb_dir)
            if not art.get("verified"):
                raise ValueError("artefact was not verified at compile time")
            if art.get("kb_digest") != kb.digest:
                raise ValueError(f"compiled for KB {art.get('kb_digest')}, service runs KB {kb.digest}")
            zones = kb.zone_names()
            if art.get("ensemble"):
                decider: Program | Ensemble = Ensemble([Program.from_json(p, zones) for p in art["ensemble"]])
            else:
                decider = Program.from_json(art["program"], zones)
            t0 = time.monotonic()
            report = await asyncio.to_thread(verify, kb, decider)
            if not report.ok:
                raise ValueError(f"re-verification failed: {report.counterexamples(3)}")
            self.artifact, self._kb, self._decider = art, kb, decider
            self.kb_digest = kb.digest
            self.status = "active"
            log.info("compiled_policy_active", path=path, kb_digest=kb.digest,
                     verify_s=round(time.monotonic() - t0, 1), coverage=report.summary()["coverage"])
        except Exception as exc:
            self.status = f"disabled: {exc}"[:300]
            log.warning("compiled_policy_disabled", path=path, error=str(exc)[:300])

    def features(self, alert, history: list[dict]) -> Features:
        return extract_features(self._kb, alert, history)

    def decide(self, alert, history: list[dict]) -> tuple[Outcome, Features]:
        f = self.features(alert, history)
        out = self._decider.evaluate(f)
        self.stats["abstained" if out.action == "abstain" else "decided"] += 1
        return out, f

    def rule_rationale(self, rule_id: str) -> tuple[str, list[str]]:
        ids = rule_id.split(":", 1)[-1].split("+")
        for r in self._decider.rules:
            if r.id in ids:
                return r.rationale, r.kb_refs
        return "", []

    def intent_for(self, alert, out: Outcome, f: Features) -> PolicyIntent:
        rationale, refs = self.rule_rationale(out.rule_id)
        src = f"{alert.src_ip.split('/')[0]}/32"
        if out.action == "DROP" and out.scope == "flow":
            dst, port = f"{alert.dest_ip.split('/')[0]}/32", int(alert.dest_port or 0)
        elif out.action == "DROP" and out.scope == "pair":
            dst, port = f"{alert.dest_ip.split('/')[0]}/32", 0
        else:
            dst, port = ("", 0) if out.action == "DROP" else (f"{alert.dest_ip.split('/')[0]}/32",
                                                               int(alert.dest_port or 0))
        steps = [f"[compiled] {out.rule_id}: {rationale}".strip(),
                 f"[compiled] KB {self.kb_digest} refs: {', '.join(refs) or '-'}",
                 f"[compiled] inputs: sid={f.sid or 'unknown'} P{f.severity} {f.src_zone}->{f.dst_zone} "
                 f"({f.verdict}) prior_alerts={f.prior_alerts} distinct_targets={f.distinct_targets} "
                 f"ports_on_target={f.ports_on_target}"]
        return PolicyIntent(
            action=PolicyAction.DROP if out.action == "DROP" else PolicyAction.LOG_ONLY,
            src_ip=src, dst_ip=dst, dst_port=port,
            protocol=(alert.proto or "tcp").lower(),
            ttl_seconds=int(out.ttl_seconds) if out.action == "DROP" else 60,
            confidence=min(max(out.confidence, 0.0), 1.0),
            comment=f"compiled policy {out.rule_id}"[:120],
            reasoning_steps=steps,
            primary_hypothesis=rationale[:200])
