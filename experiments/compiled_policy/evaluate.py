#!/usr/bin/env python3
"""Score compiled response programs and the hand-written context rule over the whole
realizable input domain of a knowledge-base snapshot.

Ground truth is derived mechanically from the knowledge base, never from a program.
For an alert carrying a catalogued signature, that signature's documented response (the
**Response** field of its prose section in sids.md) governs; severity-scoring.md states it
applies only to events without a pre-classified signature.
  unknown signature                          -> defer (no automatic decision expected)
  protected or out-of-fabric source          -> no_contain
  severity P3/P4                             -> no_contain
  documented "DROP ..."                      -> contain
  documented "DROP ... after correlation"    -> contain with a prior alert from the source
  documented "log_only ..."                  -> no_contain
Two kinds of point are left ungraded ("ambiguous") because the knowledge base does not
settle them: a correlation-conditioned signature with nothing to correlate yet, and a
log_only-documented P1/P2 signature on a denied zone pair (the pair itself is a policy
violation, baselines.md "Class A"). What each system does there is reported separately.
The documented response has no structured counterpart, so a system that reads only the
YAML fields cannot see it.

Usage: intelligence-layer/.venv/bin/python compiled_policy/evaluate.py KB_DIR ARTIFACT.json [...]
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

IL = Path(__file__).resolve().parents[2] / "intelligence-layer"
sys.path.insert(0, str(IL))
from src.compiler.dsl import Ensemble, Features, Program  # noqa: E402
from src.compiler.kb import EXTERNAL, KBSnapshot  # noqa: E402
from src.compiler.verifier import domain, realizable, verify  # noqa: E402

_RESPONSE = re.compile(r"\*\*Response\*\*:\s*([^·\n]+)")

# The hand-written context rule (Baseline-C) as deployed: its permitted-path override
# list and protected-zone list are code constants, not read from the knowledge base.
HAND_ALLOW_PATH_SIDS = frozenset({9000050, 9000051, 9000052, 9000060, 9000061, 9000062,
                                  9000070, 9000071, 9000072})
HAND_PROTECTED_ZONES = frozenset({"MGT", "MONITORING"})
HAND_SINK_ZONES = frozenset({"DB-OLTP", "DB-ANALYTICS"})


def documented_response(kb: KBSnapshot, sid: int) -> tuple[str, bool]:
    """('DROP'|'log_only'|'', needs_correlation) from the signature's prose."""
    m = _RESPONSE.search(kb.sids[sid].section) if sid in kb.sids else None
    text = (m.group(1).strip() if m else "").lower()
    if text.startswith("drop"):
        return "DROP", "after correlat" in text
    if "log_only" in text or text.startswith("log"):
        return "log_only", False
    return "", False


def oracle(kb: KBSnapshot, f: Features) -> str:
    if f.sid == 0:
        return "defer"
    if f.src_protected or f.src_zone == EXTERNAL or f.severity > 2:
        return "no_contain"
    resp, correlate = documented_response(kb, f.sid)
    if resp == "DROP":
        if correlate and f.prior_alerts == 0:
            return "ambiguous"
        return "contain"
    if f.verdict == "DENY":
        return "ambiguous"
    return "no_contain"


def baseline_c(kb: KBSnapshot, f: Features, zone_protection: bool = True) -> str:
    """Deterministic context rule, given the snapshot's zones and matrix: it adapts to
    structured changes but keeps its hand-written lists. zone_protection=False is the
    strongest variant, protecting hosts exactly as the never-block set does."""
    if f.severity > 2 or f.src_protected or f.src_zone == EXTERNAL:
        return "log_only"
    if zone_protection and f.src_zone in HAND_PROTECTED_ZONES:
        return "log_only"
    if f.verdict == "DENY":
        return "DROP"
    if f.verdict == "EXTERNAL" and f.src_zone in HAND_SINK_ZONES:
        return "DROP"
    return "DROP" if f.sid in HAND_ALLOW_PATH_SIDS else "log_only"


def baseline_c_stale(kb: KBSnapshot, f: Features) -> str:
    """The context rule exactly as deployed: zones and matrix come from the service's
    hard-coded topology, so a zone the code does not know is outside the fabric."""
    from src.core.policy import check_policy
    from src.core.topology import ZONES
    sz = f.src_zone if f.src_zone in ZONES else EXTERNAL
    dz = f.dst_zone if f.dst_zone in ZONES else EXTERNAL
    verdict = ("EXTERNAL" if EXTERNAL in (sz, dz) else "INTRA" if sz == dz else check_policy(sz, dz))
    seen = Features(f.sid, f.severity, sz, dz, verdict, f.src_protected, f.prior_alerts,
                    f.distinct_targets, f.ports_on_target)
    return baseline_c(kb, seen)


def score(kb: KBSnapshot, decide) -> dict:
    """decide(f) -> 'DROP' | 'log_only' | 'abstain'."""
    c = Counter()
    errors = Counter()
    for f in domain(kb):
        if not realizable(kb, f):
            continue
        truth, got = oracle(kb, f), decide(f)
        if truth == "defer":
            c["unknown"] += 1
            c["unknown_auto_drop"] += got == "DROP"
            continue
        if truth == "ambiguous":
            c["ambiguous"] += 1
            c[f"ambiguous_{got}"] += 1
            continue
        c["known"] += 1
        if got == "abstain":
            c["abstain"] += 1
            continue
        c["decided"] += 1
        ok = (got == "DROP") == (truth == "contain")
        c["correct"] += ok
        if truth == "contain":
            c["tp" if got == "DROP" else "fn"] += 1
        else:
            c["fp" if got == "DROP" else "tn"] += 1
        if not ok:
            errors[(f.sid, f.verdict, "FP" if got == "DROP" else "FN")] += 1
    known, dec = c["known"] or 1, c["decided"] or 1
    return {"known_points": c["known"], "coverage": round(c["decided"] / known, 4),
            "accuracy_decided": round(c["correct"] / dec, 4),
            "accuracy_all_known_abstain_as_wrong": round(c["correct"] / known, 4),
            "TP": c["tp"], "FN": c["fn"], "FP": c["fp"], "TN": c["tn"], "abstain": c["abstain"],
            "unknown_points": c["unknown"], "unknown_auto_drop": c["unknown_auto_drop"],
            "ambiguous_points": c["ambiguous"],
            "ambiguous_actions": {a: c[f"ambiguous_{a}"] for a in ("DROP", "log_only", "abstain")},
            "errors_by_sid": {f"{s}:{v}:{k}": n for (s, v, k), n in errors.most_common(15)}}


def main(kb_dir: str, artifacts: list[str]) -> dict:
    kb = KBSnapshot.load(kb_dir)
    out = {"kb_digest": kb.digest, "baseline_c": score(kb, lambda f: baseline_c(kb, f)),
           "baseline_c_host": score(kb, lambda f: baseline_c(kb, f, zone_protection=False)),
           "baseline_c_stale": score(kb, lambda f: baseline_c_stale(kb, f))}
    for p in artifacts:
        art = json.load(open(p))
        if art.get("ensemble"):
            members = [Program.from_json(x, kb.zone_names()) for x in art["ensemble"]]
            for i, m in enumerate(members):
                r = score(kb, lambda f, m=m: m.evaluate(f).action)
                r["verified"] = verify(kb, m).ok
                out[f"{Path(p).stem}.member{i}"] = r
            prog = Ensemble(members)
        elif art.get("program"):
            prog = Program.from_json(art["program"], kb.zone_names())
        else:
            out[Path(p).stem] = {"error": "no program"}
            continue
        rep = verify(kb, prog)
        res = score(kb, lambda f: prog.evaluate(f).action)
        res["verified"] = rep.ok and art.get("kb_digest") == kb.digest
        res["compile_tokens"] = art.get("usage")
        out[Path(p).stem] = res
    return out


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1], sys.argv[2:]), indent=1))
