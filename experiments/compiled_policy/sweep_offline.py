#!/usr/bin/env python3
"""The 75-case matrix sweep decided by a compiled program, offline, on the same exposure
and collateral axes as sweep_eval.py. Abstained cases are listed: in the deployed system
the runtime agent answers them.

Usage: intelligence-layer/.venv/bin/python compiled_policy/sweep_offline.py ARTIFACT.json [SWEEP_RESULT.json]
"""
import json
import sys
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXP.parent / "intelligence-layer"))
sys.path.insert(0, str(EXP / "matrix_sweep"))
from build_cases import build  # noqa: E402
from sweep_eval import alert_of, effect, ref_decisions  # noqa: E402
from src.compiler.dsl import Ensemble, Program  # noqa: E402
from src.compiler.fast_path import extract_features  # noqa: E402
from src.compiler.kb import KBSnapshot  # noqa: E402
from src.models.alert import SuricataAlert  # noqa: E402


def main(artifact, sweep_result=None):
    kb = KBSnapshot.load(EXP.parent / "intelligence-layer" / "knowledge_v2")
    art = json.load(open(artifact))
    z = kb.zone_names()
    prog = (Ensemble([Program.from_json(p, z) for p in art["ensemble"]]) if art.get("ensemble")
            else Program.from_json(art["program"], z))
    runtime = {}
    if sweep_result:
        for r in json.load(open(sweep_result))["rows"]:
            runtime.setdefault(r["case_id"], []).append(r["bizm"])
    systems = ["static_only", "soar_host", "fixed_flow", "graph_rule", "compiled", "bizm_runtime"]
    agg = {s: {"correct": 0, "n": 0, "svc": 0, "cut": 0, "obs": 0} for s in systems}
    abstained = []
    for c in build()["cases"]:
        f = extract_features(kb, SuricataAlert.from_raw(alert_of(c)), [])
        o = prog.evaluate(f)
        want = c["expected"] == "contain"
        rows = {k: effect(c, v[0], v[1]) for k, v in ref_decisions(c).items()}
        if o.action == "abstain":
            abstained.append(c["case_id"])
        rows["compiled"] = effect(c, o.action == "DROP", o.scope if o.action == "DROP" else "none")
        for s, e in rows.items():
            a = agg[s]
            if s == "compiled" and o.action == "abstain":
                continue
            a["n"] += 1
            a["correct"] += e["contains"] == want
            a["svc"] += e["service_reduction"]
            a["cut"] += e["legit_flows_cut"]
            a["obs"] += bool(e["observed_path_blocked"])
        for b in runtime.get(c["case_id"], []):
            a = agg["bizm_runtime"]
            a["n"] += 1
            a["correct"] += b["correct"]
            a["svc"] += b["service_reduction"]
            a["cut"] += b["legit_flows_cut"]
            a["obs"] += bool(b["observed_path_blocked"])
    for s in systems:
        a = agg[s]
        if a["n"]:
            print(f"{s:13s} n={a['n']:4d} acc={a['correct']/a['n']:.3f} svc_closed={a['svc']:4d} "
                  f"obs_blocked={a['obs']:4d} legit_cut={a['cut']:4d}  (per decision cut={a['cut']/a['n']:.2f})")
    print("compiled abstained:", abstained)


if __name__ == "__main__":
    main(*sys.argv[1:3])
