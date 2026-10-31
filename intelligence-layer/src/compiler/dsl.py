"""The response-program language the compiler emits.

A program is an ordered list of rules; the first rule whose conditions all hold decides,
and an alert no rule matches is ABSTAIN (handed to the runtime agent). Conditions range
over a closed set of alert features that are either read from the alert or looked up in
the knowledge base, so the set of distinct inputs is finite and every program can be
checked on all of them (see verifier.py).

The language has no field for the rule target: an enforced rule always blocks the alert
source as a /32, and its destination and port follow from the scope. Target fidelity
(I2) therefore holds by construction and cannot be violated by a compiled program.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ACTIONS = ("DROP", "log_only", "abstain")
SCOPES = ("flow", "pair", "host")
VERDICTS = ("ALLOW", "DENY", "INTRA", "EXTERNAL")


@dataclass(frozen=True)
class Features:
    """One point of the input domain."""
    sid: int                 # 0 = signature not in the catalogue
    severity: int            # 1 (critical) .. 4 (audit)
    src_zone: str            # zone name or EXTERNAL
    dst_zone: str
    verdict: str             # ALLOW | DENY | INTRA | EXTERNAL
    src_protected: bool      # source address is in the never-block set
    prior_alerts: int        # earlier alerts from this source in the correlation window (0, 1+)
    distinct_targets: int = 0   # other destinations this source was alerted on (0, 1, 2+)
    ports_on_target: int = 0    # other ports on this same destination already alerted (0, 1+)


@dataclass(frozen=True)
class Outcome:
    action: str
    scope: str = "flow"
    ttl_seconds: int = 0
    confidence: float = 0.0
    rule_id: str = "default"


ABSTAIN = Outcome("abstain")

_WHEN = {
    "sids": {"type": ["array", "null"], "items": {"type": "integer"}},
    "sid_known": {"type": ["boolean", "null"]},
    "severity_min": {"type": ["integer", "null"]},
    "severity_max": {"type": ["integer", "null"]},
    "src_zones": {"type": ["array", "null"], "items": {"type": "string"}},
    "dst_zones": {"type": ["array", "null"], "items": {"type": "string"}},
    "verdicts": {"type": ["array", "null"], "items": {"type": "string", "enum": list(VERDICTS)}},
    "src_protected": {"type": ["boolean", "null"]},
    "prior_alerts_min": {"type": ["integer", "null"]},
    "distinct_targets_min": {"type": ["integer", "null"]},
    "ports_on_target_min": {"type": ["integer", "null"]},
}

PROGRAM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "when": {"type": "object", "properties": _WHEN},
                    "then": {
                        "type": "object",
                        "properties": {
                            "action": {"type": "string", "enum": list(ACTIONS)},
                            "scope": {"type": "string", "enum": list(SCOPES)},
                            "ttl_seconds": {"type": "integer"},
                            "confidence": {"type": "number"},
                        },
                        "required": ["action"],
                    },
                    "rationale": {"type": "string"},
                    "kb_refs": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["id", "when", "then", "rationale"],
            },
        },
        "notes": {"type": "string"},
    },
    "required": ["rules"],
}


class ProgramError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    when: dict
    then: Outcome
    rationale: str
    kb_refs: list[str]

    def matches(self, f: Features) -> bool:
        w = self.when
        if w.get("sids") is not None and f.sid not in w["sids"]:
            return False
        if w.get("sid_known") is not None and (f.sid != 0) != w["sid_known"]:
            return False
        if w.get("severity_min") is not None and f.severity < w["severity_min"]:
            return False
        if w.get("severity_max") is not None and f.severity > w["severity_max"]:
            return False
        if w.get("src_zones") is not None and f.src_zone not in w["src_zones"]:
            return False
        if w.get("dst_zones") is not None and f.dst_zone not in w["dst_zones"]:
            return False
        if w.get("verdicts") is not None and f.verdict not in w["verdicts"]:
            return False
        if w.get("src_protected") is not None and f.src_protected != w["src_protected"]:
            return False
        if w.get("prior_alerts_min") is not None and f.prior_alerts < w["prior_alerts_min"]:
            return False
        if w.get("distinct_targets_min") is not None and f.distinct_targets < w["distinct_targets_min"]:
            return False
        if w.get("ports_on_target_min") is not None and f.ports_on_target < w["ports_on_target_min"]:
            return False
        return True


@dataclass
class Program:
    rules: list[Rule]
    notes: str = ""

    @classmethod
    def from_json(cls, data: dict, known_zones: list[str] | None = None) -> "Program":
        """Parse and structurally check a program. Raises ProgramError."""
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise ProgramError("program must be an object with a 'rules' array")
        zones = set(known_zones or []) | {"EXTERNAL"}
        rules, seen = [], set()
        for i, r in enumerate(data["rules"]):
            if not isinstance(r, dict):
                raise ProgramError(f"rule #{i} is not an object")
            rid = str(r.get("id") or f"R{i + 1}")
            if rid in seen:
                rid = f"{rid}#{i + 1}"
            seen.add(rid)
            when = {k: v for k, v in (r.get("when") or {}).items() if k in _WHEN and v is not None}
            unknown = set((r.get("when") or {})) - set(_WHEN)
            if unknown:
                raise ProgramError(f"rule {rid}: unknown condition(s) {sorted(unknown)}")
            for key in ("src_zones", "dst_zones"):
                bad = [z for z in when.get(key, []) if known_zones is not None and z not in zones]
                if bad:
                    raise ProgramError(f"rule {rid}: unknown zone(s) {bad} in {key}")
            for v in when.get("verdicts", []):
                if v not in VERDICTS:
                    raise ProgramError(f"rule {rid}: unknown verdict {v!r}")
            t = r.get("then") or {}
            action = t.get("action")
            if action not in ACTIONS:
                raise ProgramError(f"rule {rid}: action {action!r} not in {ACTIONS}")
            scope = t.get("scope") or "flow"
            if scope not in SCOPES:
                raise ProgramError(f"rule {rid}: scope {scope!r} not in {SCOPES}")
            outcome = Outcome(action, scope, int(t.get("ttl_seconds") or 0),
                              float(t.get("confidence") or 0.0), rid)
            rules.append(Rule(rid, when, outcome, str(r.get("rationale") or ""),
                              [str(x) for x in (r.get("kb_refs") or [])]))
        return cls(rules, str(data.get("notes") or ""))

    def evaluate(self, f: Features) -> Outcome:
        for r in self.rules:
            if r.matches(f):
                return r.then
        return ABSTAIN

    def to_json(self) -> dict:
        return {"rules": [{"id": r.id, "when": r.when,
                           "then": {"action": r.then.action, "scope": r.then.scope,
                                    "ttl_seconds": r.then.ttl_seconds,
                                    "confidence": r.then.confidence},
                           "rationale": r.rationale, "kb_refs": r.kb_refs} for r in self.rules],
                "notes": self.notes}


SCOPE_ORDER = {"flow": 0, "pair": 1, "host": 2}


@dataclass
class Ensemble:
    """Several independently compiled programs combined point-wise.

    An action is taken only when a strict majority of programs chooses it; otherwise
    the ensemble abstains. Among the agreeing programs the most conservative parameters
    are kept (narrowest scope, shortest TTL, lowest confidence), so the combined
    decision is never wider than what any agreeing program would have enforced.
    """
    programs: list[Program]

    @property
    def rules(self) -> list[Rule]:
        return [r for p in self.programs for r in p.rules]

    def evaluate(self, f: Features) -> Outcome:
        outs = [p.evaluate(f) for p in self.programs]
        counts: dict[str, list[Outcome]] = {}
        for o in outs:
            counts.setdefault(o.action, []).append(o)
        action, agree = max(counts.items(), key=lambda kv: len(kv[1]))
        if len(agree) * 2 <= len(outs) or action == "abstain":
            return Outcome("abstain", rule_id="ensemble:no-majority" if action != "abstain" else "default")
        if action != "DROP":
            return Outcome(action, rule_id="ensemble")
        return Outcome("DROP",
                       scope=min((o.scope for o in agree), key=SCOPE_ORDER.__getitem__),
                       ttl_seconds=min(o.ttl_seconds for o in agree),
                       confidence=min(o.confidence for o in agree),
                       rule_id="ensemble:" + "+".join(sorted({o.rule_id for o in agree})))
