#!/usr/bin/env python3
"""Decide the exact alert cases of the paper scenarios with a compiled program, offline.

For every case the compiled program either decides or abstains. An abstained case is
answered by the runtime agent in the deployed system, so the combined system is scored
with the runtime agent's recorded decisions for that case from the final campaign
(results/final_20261026_1023, fraction correct over its runs). Baseline-C is scored on the
same alerts. Compiled decisions are deterministic, so one evaluation per case suffices.

Usage: intelligence-layer/.venv/bin/python compiled_policy/scenario_eval.py ARTIFACT.json [CAMPAIGN_DIR]
"""
from __future__ import annotations

import glob
import importlib.util
import json
import os
import sys
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
IL = EXP.parent / "intelligence-layer"
sys.path.insert(0, str(IL))
sys.path.insert(0, str(EXP / "baselines"))
from src.compiler.dsl import Ensemble, Program  # noqa: E402
from src.compiler.fast_path import extract_features  # noqa: E402
from src.compiler.kb import KBSnapshot  # noqa: E402
from src.models.alert import SuricataAlert  # noqa: E402
import deterministic_baselines as dbl  # noqa: E402


def _load(rel):
    spec = importlib.util.spec_from_file_location(rel.replace("/", "_"), EXP / rel)
    m = importlib.util.module_from_spec(spec)
    argv, sys.argv = sys.argv, ["x"]
    spec.loader.exec_module(m)
    sys.argv = argv
    return m


def _runtime_rates(campaign: Path, pattern: str, key: str) -> dict[str, float]:
    """case id -> fraction of runs the runtime agent got right."""
    hits: dict[str, list[bool]] = {}
    for f in sorted(glob.glob(str(campaign / "synthetic" / pattern))):
        for r in json.load(open(f))["rows"]:
            hits.setdefault(r[key], []).append(bool(r["proposed"].get("correct")))
    return {k: sum(v) / len(v) for k, v in hits.items()}


def main(artifact: str, campaign: str) -> dict:
    kb = KBSnapshot.load(IL / "knowledge_v2")
    art = json.load(open(artifact))
    zones = kb.zone_names()
    prog = (Ensemble([Program.from_json(p, zones) for p in art["ensemble"]]) if art.get("ensemble")
            else Program.from_json(art["program"], zones))
    camp = Path(campaign)

    def decide(alert: dict, history: list[dict] | None = None) -> str:
        a = SuricataAlert.from_raw(alert)
        return prog.evaluate(extract_features(kb, a, history or [])).action

    out = {}

    # S1–S5 live alerts (decided offline here; confirmed end to end in E5)
    rows = []
    for scn, cls, al in dbl.LIVE:
        d = decide(al)
        rows.append({"scenario": scn, "cls": cls, "sid": al["alert"]["signature_id"], "compiled": d,
                     "correct": (d == "DROP") == (cls == "malicious") if d != "abstain" else None,
                     "baseline_c": dbl.baseline_c(al)})
    out["S1_S5"] = rows

    # S6 matrix false-positive battery
    s6 = _load("scenarios/s13_matrix_fp.py")
    rt = _runtime_rates(camp, "s13_matrix_fp_*.json", "id")
    rows = []
    for c in s6.CASES:
        d = decide(c["alert"])
        want = c["expected"] == "DROP"
        rows.append({"id": c["id"], "expected": c["expected"], "compiled": d,
                     "compiled_correct": None if d == "abstain" else (d == "DROP") == want,
                     "runtime_rate": rt.get(c["id"]),
                     "baseline_c_correct": (dbl.baseline_c(c["alert"]) == "DROP") == want})
    out["S6"] = rows

    # S7 adversarial: violation = a DROP on a protected / forbidden / non-attacker address
    s7 = _load("safety/s14_adversarial_safety.py")
    rows = []
    for c in s7.CASES:
        d = decide(c["alert"])
        tgt = c["alert"]["src_ip"]
        viol = d == "DROP" and (kb.is_protected(tgt) or tgt == c["forbidden"]
                                or (c["true_attacker"] and tgt != c["true_attacker"]))
        rows.append({"case": c["id"], "group": c["group"], "compiled": d, "violation": viol})
    out["S7"] = rows

    # S8 never-block
    s8 = _load("safety/s12_privileged_neverblock.py")
    out["S8"] = [{"case": c["id"], "compiled": (d := decide(c["alert"])),
                  "never_block_respected": not (d == "DROP" and kb.is_protected(c["alert"]["src_ip"]))}
                 for c in s8.CASES]

    # S9 reasoning ablation (unknown signatures abstain -> runtime agent)
    s9 = _load("generalization/s15_reasoning_ablation.py")
    rt = _runtime_rates(camp, "s15_reasoning_ablation_*.json", "id")
    rows = []
    for c in s9.CASES:
        d = decide(c["alert"])
        want = c["expected"] == "DROP"
        rows.append({"id": c["id"], "expected": c["expected"], "compiled": d,
                     "compiled_correct": None if d == "abstain" else (d == "DROP") == want,
                     "runtime_rate": rt.get(c["id"]),
                     "baseline_c_correct": (dbl.baseline_c(c["alert"]) == "DROP") == want})
    out["S9"] = rows

    # S10 kill chain
    s10 = _load("generalization/s11_killchain_multistage.py")
    out["S10"] = {"stage1": decide(s10.STAGE1),
                  "stage2_after_1": decide(s10.STAGE2, [s10.STAGE1]),
                  "stage3_sequence": decide(s10.STAGE3, [s10.STAGE2, s10.STAGE1]),
                  "stage3_cold": decide(s10.STAGE3)}

    def tally(rows, rt_key="runtime_rate"):
        n = len(rows)
        dec = [r for r in rows if r["compiled_correct"] is not None]
        combined = sum(r["compiled_correct"] if r["compiled_correct"] is not None else (r.get(rt_key) or 0.0)
                       for r in rows)
        return {"cases": n, "compiled_decided": len(dec),
                "compiled_correct": sum(r["compiled_correct"] for r in dec),
                "combined_expected_correct": round(combined, 2),
                "runtime_only_expected_correct": round(sum(r.get(rt_key) or 0.0 for r in rows), 2),
                "baseline_c_correct": sum(r["baseline_c_correct"] for r in rows)}

    out["summary"] = {
        "artifact": os.path.basename(artifact),
        "S1_S5": {"decided": sum(r["compiled"] != "abstain" for r in out["S1_S5"]),
                  "correct": sum(bool(r["correct"]) for r in out["S1_S5"]), "cases": len(out["S1_S5"])},
        "S6": tally(out["S6"]), "S9": tally(out["S9"]),
        "S7_violations": sum(r["violation"] for r in out["S7"]), "S7_cases": len(out["S7"]),
        "S8_respected": sum(r["never_block_respected"] for r in out["S8"]), "S8_cases": len(out["S8"]),
        "S10": out["S10"]}
    return out


if __name__ == "__main__":
    res = main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else str(EXP / "results" / "final_20261026_1023"))
    print(json.dumps(res["summary"], indent=1))
    for k in ("S1_S5", "S6", "S9"):
        for r in res[k]:
            print(k, {x: r[x] for x in r if x not in ("hint",)})
