#!/usr/bin/env python3
"""Score a synthesis pool (synth_pool.py) for the loop dynamics, the ablation and the
ensemble-size sensitivity.

Every candidate is scored with the RQ1 grader (evaluate.oracle) on the realizable points;
"unsafe" counts DROP decisions on graded points whose source is protected or outside the
fabric. Ensembles follow dsl.Ensemble: a strict majority of members must agree on the
action, otherwise the ensemble abstains.

Arms (one pool, read at different stages of each run):
  one_shot      round-0 draft, deployed whether or not it verifies
  repair        converged draft (verified), discarded when the round budget is exhausted
  repair_review final program of the run
  ensemble_k    strict-majority vote of k finals drawn without replacement

Usage: intelligence-layer/.venv/bin/python compiled_policy/synth_eval.py KB_DIR POOL_DIR OUT.json
"""
from __future__ import annotations

import itertools
import json
import math
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import oracle  # noqa: E402
from src.compiler.dsl import Program  # noqa: E402
from src.compiler.kb import EXTERNAL, KBSnapshot  # noqa: E402
from src.compiler.verifier import domain, realizable  # noqa: E402

T95 = {19: 2.093, 29: 2.045, 9: 2.262, 4: 2.776, 14: 2.145, 24: 2.064}


def ci(xs):
    n = len(xs)
    if n == 0:
        return None
    m = sum(xs) / n
    if n == 1:
        return [round(m, 4), round(m, 4), round(m, 4)]
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1))
    h = T95.get(n - 1, 1.96) * sd / math.sqrt(n)
    return [round(m, 4), round(m - h, 4), round(m + h, 4)]


def mcnemar(b, c):
    """Exact two-sided McNemar p from discordant counts b, c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


class Grader:
    def __init__(self, kb):
        self.kb = kb
        self.pts = [f for f in domain(kb) if realizable(kb, f)]
        self.truth = [oracle(kb, f) for f in self.pts]
        self.graded = [i for i, t in enumerate(self.truth) if t in ("contain", "no_contain")]
        self.unsafe_ok = {i for i in self.graded
                          if self.pts[i].src_protected or self.pts[i].src_zone == EXTERNAL}

    def vector(self, prog_json):
        p = Program.from_json(prog_json, self.kb.zone_names())
        return [p.evaluate(f).action for f in self.pts]

    def metrics(self, vec):
        dec = corr = unsafe = 0
        for i in self.graded:
            a = vec[i]
            if a == "abstain":
                continue
            dec += 1
            corr += (a == "DROP") == (self.truth[i] == "contain")
            unsafe += a == "DROP" and i in self.unsafe_ok
        n = len(self.graded)
        return {"acc": corr / dec if dec else None, "cov": dec / n, "unsafe": unsafe,
                "abstain": n - dec, "correct": corr, "decided": dec}

    def correct_set(self, vec):
        return {i for i in self.graded if vec[i] != "abstain"
                and (vec[i] == "DROP") == (self.truth[i] == "contain")}


def vote(vecs):
    out = []
    for acts in zip(*vecs):
        a, n = Counter(acts).most_common(1)[0]
        out.append(a if n * 2 > len(acts) and a != "abstain" else "abstain")
    return out


def main(kb_dir, pool_dir, out_path):
    kb = KBSnapshot.load(kb_dir)
    g = Grader(kb)
    runs = [json.load(open(p)) for p in sorted(Path(pool_dir).glob("run_*.json"))]
    runs = [r for r in runs if r["kb_digest"] == kb.digest]
    per = []
    for r in runs:
        rounds = r["rounds"]
        drafts = [x for x in rounds if x["stage"] == "draft"]
        r0 = drafts[0]
        rep = drafts[-1] if drafts[-1].get("ok") else None
        row = {"run": r["run"], "tokens": r["usage"]["prompt_tokens"] + r["usage"]["completion_tokens"],
               "r0_ok": bool(r0.get("ok")), "r0_parse_error": "parse_error" in r0,
               "ce0": r0.get("violation_kinds", 0) + r0.get("provenance_errors", 0),
               "ce0_by_check": (r0.get("by_check") or {}).get("counterexamples", {}),
               "viol0_by_check": (r0.get("by_check") or {}).get("points", {}),
               "violating_points0": r0.get("violating_points", 0),
               "repair_rounds": len(drafts) - 1, "repair_ok": rep is not None,
               "review_rounds": sum(1 for x in rounds if x["stage"] == "review"),
               "final_verified": r["verified"]}
        vecs = {}
        if "candidate" in r0:
            vecs["one_shot"] = g.vector(r0["candidate"])
        if rep is not None:
            vecs["repair"] = g.vector(rep["candidate"])
        if r["final"]:
            vecs["repair_review"] = g.vector(r["final"])
        for k, v in vecs.items():
            row[k] = g.metrics(v)
        if "repair" in vecs and "repair_review" in vecs:
            row["review_changed_graded"] = sum(vecs["repair"][i] != vecs["repair_review"][i] for i in g.graded)
        row["_vecs"] = vecs
        per.append(row)

    n = len(per)
    arms = {}
    for arm in ("one_shot", "repair", "repair_review"):
        have = [p for p in per if arm in p]
        arms[arm] = {"n": n, "deployable": len(have),
                     "verified_frac": (sum(p["r0_ok"] for p in per) if arm == "one_shot"
                                       else len(have)) / n,
                     "acc": ci([p[arm]["acc"] for p in have if p[arm]["acc"] is not None]),
                     "cov": ci([p[arm]["cov"] for p in have]),
                     "unsafe_total": sum(p[arm]["unsafe"] for p in have),
                     "unsafe_runs": sum(p[arm]["unsafe"] > 0 for p in have)}
    arms["repair"]["rounds_mean"] = round(sum(p["repair_rounds"] for p in per if p["repair_ok"])
                                          / max(1, sum(p["repair_ok"] for p in per)), 2)
    # paired McNemar between consecutive arms over (run, graded point), counting a point as
    # correct when it is decided correctly
    def pair_test(a, b):
        bb = cc = 0
        for p in per:
            if a in p["_vecs"] and b in p["_vecs"]:
                sa, sb = g.correct_set(p["_vecs"][a]), g.correct_set(p["_vecs"][b])
                bb += len(sa - sb)
                cc += len(sb - sa)
        return {"a_only": bb, "b_only": cc, "p": mcnemar(bb, cc)}
    tests = {"verify_oneshot_vs_repair": {"p": mcnemar(0, sum(1 for p in per if p["repair_ok"] and not p["r0_ok"]))},
             "points_oneshot_vs_repair": pair_test("one_shot", "repair"),
             "points_repair_vs_review": pair_test("repair", "repair_review")}

    finals = [p for p in per if "repair_review" in p["_vecs"]]
    rnd = random.Random(7)
    ens = {}
    for k in (1, 3, 5, 7, 9):
        if k > len(finals):
            continue
        combos = set()
        tries = 0
        while len(combos) < 20 and tries < 2000:
            combos.add(tuple(sorted(rnd.sample(range(len(finals)), k))))
            tries += 1
        rows = []
        for c in combos:
            mem = [finals[i] for i in c]
            v = mem[0]["_vecs"]["repair_review"] if k == 1 else vote([m["_vecs"]["repair_review"] for m in mem])
            m = g.metrics(v)
            m["tokens"] = sum(x["tokens"] for x in mem)
            m["pass0"] = sum(x["r0_ok"] for x in mem) / k
            m["rounds"] = sum(x["repair_rounds"] for x in mem) / k
            rows.append(m)
        ens[k] = {"ensembles": len(rows), "acc": ci([r["acc"] for r in rows if r["acc"] is not None]),
                  "acc_min": min(r["acc"] for r in rows if r["acc"] is not None),
                  "cov": ci([r["cov"] for r in rows]), "abstain_mean": ci([r["abstain"] for r in rows]),
                  "unsafe_total": sum(r["unsafe"] for r in rows), "tokens_mean": ci([r["tokens"] for r in rows]),
                  "pass0": ci([r["pass0"] for r in rows]), "rounds": ci([r["rounds"] for r in rows])}
    for p in per:
        p.pop("_vecs")
    ce_tot = Counter()
    for p in per:
        ce_tot.update(p["ce0_by_check"])
    res = {"kb": kb.digest, "graded_points": len(g.graded), "runs": n, "per_run": per, "arms": arms,
           "tests": tests, "ensemble_size": ens,
           "round0_failed": sum(not p["r0_ok"] for p in per), "ce0_total_by_check": dict(ce_tot),
           "discarded": sum(not p["final_verified"] for p in per)}
    Path(out_path).write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != "per_run"}, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:4])
