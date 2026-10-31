"""Exhaustive verification of a compiled response program.

The input domain is finite: (signature × severity × source zone × destination zone ×
protected-source flag × prior-alert bucket), with zones taken from the knowledge-base
snapshot plus EXTERNAL, and an extra "unknown signature" value. The verifier evaluates
the program on every point and checks the safety invariants on each decision, so a
program that passes holds the invariants for every alert it can receive, including
spoofed and internally inconsistent ones, not only for the alerts in a test set.

Checked on every point (all are necessary conditions the runtime validators also
enforce, so a verified program is never rejected downstream for these reasons):
  I3  a DROP never targets a protected or out-of-fabric source
  I4  DROP TTL within bounds; host scope only for P1 with shortened TTL; a DROP on a
      permitted (ALLOW) path is flow scope with shortened TTL and confidence >= 0.90
  I5  a DROP requires severity P1/P2 and confidence >= the auto-enforce threshold
  I6  a DROP rule carries a rationale and cites the knowledge base; cited signatures exist
  G1  a DROP is grounded in the catalogue: unknown signatures never auto-enforce
I1 (DROP-only action set) and I2 (target = alert source) hold by construction of the
language.
"""
from __future__ import annotations

import itertools
import re
from collections import defaultdict
from dataclasses import dataclass, field

from ..core.invariants import TTL_MAX_SECONDS, TTL_MIN_SECONDS
from ..agent.safety.validators import SEMANTIC_OVERRIDE_TTL_MAX
from .dsl import Ensemble, Features, Outcome, Program
from .kb import EXTERNAL, KBSnapshot

AUTO_ENFORCE_CONFIDENCE = 0.85
OVERRIDE_CONFIDENCE = 0.90
HOST_SCOPE_TTL_MAX = 1800
# (prior_alerts, distinct_targets, ports_on_target): a source with no earlier alert has
# no history to fan out from.
HISTORY_BUCKETS = ((0, 0, 0), (1, 0, 0), (1, 0, 1), (1, 1, 0), (1, 1, 1), (1, 2, 0), (1, 2, 1))
_SID_REF = re.compile(r"\b(?:SID\s*)?(9\d{6}|[1-8]\d{6})\b")


def domain(kb: KBSnapshot):
    zones = kb.zone_names() + [EXTERNAL]
    sids = sorted(kb.sids) + [0]
    for sid, sev, sz, dz, prot, (prior, targets, ports) in itertools.product(
            sids, (1, 2, 3, 4), zones, zones, (False, True), HISTORY_BUCKETS):
        yield Features(sid, sev, sz, dz, kb.verdict(sz, dz), prot, prior, targets, ports)


def realizable(kb: KBSnapshot, f: Features) -> bool:
    """Inputs the deployed IDS can actually emit: a catalogued signature carries its
    catalogued severity and fires only on the zone pairs its detection logic covers."""
    if f.src_zone == f.dst_zone and f.src_zone != EXTERNAL:
        return False
    if f.src_zone == EXTERNAL and f.dst_zone == EXTERNAL:
        return False
    if f.sid == 0:
        return True
    sig = kb.sids[f.sid]
    if f.severity != sig.severity:
        return False
    pairs = kb.sid_pairs(f.sid)
    return pairs is None or (f.src_zone, f.dst_zone) in pairs


def _check(kb: KBSnapshot, f: Features, o: Outcome) -> list[str]:
    if o.action != "DROP":
        return []
    bad = []
    if f.src_protected:
        bad.append("I3: DROP on a protected source")
    if f.src_zone == EXTERNAL:
        bad.append("I3: DROP on a source outside the fabric zones")
    if f.severity > 2:
        bad.append(f"I5: DROP on severity P{f.severity}")
    if o.confidence < AUTO_ENFORCE_CONFIDENCE:
        bad.append(f"I5: DROP with confidence {o.confidence} < {AUTO_ENFORCE_CONFIDENCE}")
    if not TTL_MIN_SECONDS <= o.ttl_seconds <= TTL_MAX_SECONDS:
        bad.append(f"I4: TTL {o.ttl_seconds} outside [{TTL_MIN_SECONDS}, {TTL_MAX_SECONDS}]")
    if o.scope == "host" and (f.severity != 1 or o.ttl_seconds > HOST_SCOPE_TTL_MAX):
        bad.append("I4: host scope requires P1 and TTL <= 1800")
    if f.verdict == "ALLOW" and (o.scope != "flow" or o.ttl_seconds > SEMANTIC_OVERRIDE_TTL_MAX
                                 or o.confidence < OVERRIDE_CONFIDENCE):
        bad.append("I4: DROP on a permitted path must be flow scope, TTL <= 1800, confidence >= 0.90")
    if f.sid == 0:
        bad.append("G1: DROP on a signature absent from the catalogue")
    return bad


def _provenance(kb: KBSnapshot, prog: Program | Ensemble) -> list[tuple[str, str]]:
    out = []
    for r in prog.rules:
        if r.then.action != "DROP":
            continue
        if not r.rationale.strip() or not r.kb_refs:
            out.append((r.id, "I6: DROP rule without rationale or knowledge-base citation"))
        for ref in r.kb_refs:
            for s in _SID_REF.findall(ref):
                if int(s) not in kb.sids:
                    out.append((r.id, f"I6: cites signature {s} absent from the catalogue"))
        for s in r.when.get("sids", []):
            if s not in kb.sids:
                out.append((r.id, f"I6: condition names signature {s} absent from the catalogue"))
    return out


@dataclass
class Report:
    n_points: int = 0
    n_realizable: int = 0
    violations: dict = field(default_factory=dict)   # (rule_id, message) -> [count, example]
    provenance: list = field(default_factory=list)
    decided_realizable: int = 0
    drop_realizable: int = 0
    abstain_realizable: int = 0
    rule_hits: dict = field(default_factory=dict)
    dead_rules: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations and not self.provenance

    def counterexamples(self, limit: int = 12) -> list[str]:
        lines = [f"rule {rid}: {msg}" for rid, msg in self.provenance]
        for (rid, msg), (n, f) in sorted(self.violations.items(), key=lambda kv: -kv[1][0])[:limit]:
            lines.append(f"rule {rid}: {msg} — {n} inputs, e.g. sid={f.sid or 'unknown'} "
                         f"P{f.severity} {f.src_zone}->{f.dst_zone} ({f.verdict}) "
                         f"protected_src={f.src_protected} prior_alerts={f.prior_alerts} "
                         f"distinct_targets={f.distinct_targets} ports_on_target={f.ports_on_target}")
        return lines

    def summary(self) -> dict:
        return {"ok": self.ok, "points": self.n_points, "realizable": self.n_realizable,
                "violating_points": sum(v[0] for v in self.violations.values()),
                "violation_kinds": len(self.violations), "provenance_errors": len(self.provenance),
                "realizable_decided": self.decided_realizable,
                "realizable_drop": self.drop_realizable,
                "realizable_abstain": self.abstain_realizable,
                "coverage": round(self.decided_realizable / self.n_realizable, 4) if self.n_realizable else 0,
                "dead_rules": self.dead_rules}


def verify(kb: KBSnapshot, prog: Program | Ensemble) -> Report:
    rep = Report()
    hits: dict[str, int] = defaultdict(int)
    for f in domain(kb):
        rep.n_points += 1
        o = prog.evaluate(f)
        hits[o.rule_id] += 1
        for msg in _check(kb, f, o):
            key = (o.rule_id, msg)
            if key in rep.violations:
                rep.violations[key][0] += 1
            else:
                rep.violations[key] = [1, f]
        if realizable(kb, f):
            rep.n_realizable += 1
            if o.action == "abstain":
                rep.abstain_realizable += 1
            else:
                rep.decided_realizable += 1
                rep.drop_realizable += o.action == "DROP"
    rep.provenance = _provenance(kb, prog)
    rep.rule_hits = dict(hits)
    if isinstance(prog, Program):
        rep.dead_rules = [r.id for r in prog.rules if not hits.get(r.id)]
    return rep


def behaviour_summary(kb: KBSnapshot, prog: Program | Ensemble) -> str:
    """What the program does on every realizable alert from an ordinary (unprotected,
    in-fabric) source, per signature and policy verdict — the view a reviewer needs to
    compare the program against the knowledge base."""
    by: dict[tuple[int, str], dict[str, list[Features]]] = defaultdict(lambda: defaultdict(list))
    for f in domain(kb):
        if f.src_protected or f.src_zone == EXTERNAL or not realizable(kb, f):
            continue
        o = prog.evaluate(f)
        key = o.action if o.action != "DROP" else f"DROP/{o.scope}/ttl{o.ttl_seconds}"
        by[(f.sid, f.verdict)][key].append(f)

    def hist(f: Features) -> str:
        if not f.prior_alerts:
            return "no prior alert"
        return (f"prior alert, {f.distinct_targets} other target(s), "
                f"{'other ports on target' if f.ports_on_target else 'same port only'}")

    lines = []
    for sid in sorted(kb.sids) + [0]:
        name = f"SID {sid} (P{kb.sids[sid].severity}, {kb.sids[sid].msg})" if sid else "unknown signature"
        for verdict in ("DENY", "ALLOW", "EXTERNAL"):
            groups = by.get((sid, verdict))
            if not groups:
                continue
            total = sum(len(v) for v in groups.values())
            if len(groups) == 1:
                lines.append(f"- {name} on {verdict} pairs: {next(iter(groups))} (all {total} inputs)")
                continue
            parts = []
            for key, fs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
                ex = fs[0]
                parts.append(f"{key} on {len(fs)} (e.g. {ex.src_zone}->{ex.dst_zone}, P{ex.severity}, {hist(ex)})")
            lines.append(f"- {name} on {verdict} pairs: " + "; ".join(parts))
    return "\n".join(lines)
