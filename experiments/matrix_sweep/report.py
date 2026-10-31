#!/usr/bin/env python3
"""Turn one or more sweep result files into the tables the paper reports.

Prints: the static configuration table, the containment/collateral comparison across
systems with Clopper-Pearson intervals on accuracy, a breakdown by policy verdict, the
per-case disagreements between BIZM and the deterministic reference systems, and a
McNemar test for each pairwise comparison against BIZM.

Usage: report.py results/matrix_sweep_*.json
"""
from __future__ import annotations

import glob
import json
import sys
from math import comb


def cp_interval(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Clopper-Pearson exact interval, by bisection on the binomial tail."""
    if n == 0:
        return (0.0, 1.0)

    def cdf(kk: int, p: float) -> float:
        return sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(kk + 1))

    def bisect(f) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2
            if f(mid):
                hi = mid
            else:
                lo = mid
        return (lo + hi) / 2

    low = 0.0 if k == 0 else bisect(lambda p: 1 - cdf(k - 1, p) >= alpha / 2)
    high = 1.0 if k == n else bisect(lambda p: cdf(k, p) <= alpha / 2)
    return low, high


def mcnemar(b: int, c: int) -> tuple[int, int, float]:
    """Exact two-sided McNemar on discordant pairs (b: only A right, c: only B right)."""
    n = b + c
    if n == 0:
        return b, c, 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(k + 1)) / 2 ** n
    return b, c, min(1.0, 2 * tail)


def load(paths: list[str]) -> tuple[list[dict], dict]:
    rows, static = [], {}
    for p in sorted(paths):
        d = json.load(open(p))
        rows += d["rows"]
        static = d["summary"].get("static_configurations", static)
    return rows, static


def side(row: dict, system: str) -> dict:
    return row["bizm"] if system == "bizm" else row["systems"][system]


def main(paths: list[str]) -> None:
    rows, static = load(paths)
    if not rows:
        sys.exit("no rows")
    systems = ["static_only", "soar_host", "fixed_flow", "graph_rule", "bizm"]

    print(f"decisions: {len(rows)}  cases: {len({r['case_id'] for r in rows})}  "
          f"repeats: {max(r.get('repeat', 1) for r in rows)}\n")

    print("== Static configurations (no runtime response) ==")
    print(f"{'configuration':28s} {'edges':>6s} {'ENICE':>6s} {'CJR':>5s} {'MPL':>6s}")
    for name, m in static.items():
        print(f"{name:28s} {m['n_edges']:6d} {m['ENICE']:6d} {m['CJR']:5d} {m['MPL']:6.2f}")

    print("\n== Containment vs collateral, all decisions ==")
    hdr = (f"{'system':13s} {'acc':>6s} {'95% CI':>14s} {'TP':>4s} {'FN':>4s} {'FP':>4s} "
           f"{'Δzone':>6s} {'Δsvc':>5s} {'obsBlk':>7s} {'cjCont':>7s} {'cut':>4s} {'crit':>5s}")
    print(hdr)
    for s in systems:
        rs = [side(r, s) for r in rows]
        ok = sum(x["correct"] for x in rs)
        lo, hi = cp_interval(ok, len(rs))
        tp = sum(1 for r, x in zip(rows, rs) if r["expected"] == "contain" and x["contains"])
        fn = sum(1 for r, x in zip(rows, rs) if r["expected"] == "contain" and not x["contains"])
        fp = sum(1 for r, x in zip(rows, rs) if r["expected"] == "no_contain" and x["contains"])
        print(f"{s:13s} {ok/len(rs):6.3f} [{lo*100:5.1f},{hi*100:5.1f}] {tp:4d} {fn:4d} {fp:4d} "
              f"{sum(x['exposure_reduction'] for x in rs):6d} "
              f"{sum(x['service_reduction'] for x in rs):5d} "
              f"{sum(bool(x['observed_path_blocked']) for x in rs):7d} "
              f"{sum(bool(x['crown_jewel_contained']) for x in rs):7d} "
              f"{sum(x['legit_flows_cut'] for x in rs):4d} "
              f"{sum(1 for x in rs if x['max_cut_criticality']=='critical'):5d}")

    for verdict in ("DENY", "ALLOW"):
        sub = [r for r in rows if r["policy_verdict"] == verdict]
        if not sub:
            continue
        print(f"\n== {verdict} cells only ({len(sub)} decisions) ==")
        print(f"{'system':13s} {'acc':>6s} {'Δsvc':>5s} {'obsBlk':>7s} {'cut':>4s}")
        for s in systems:
            rs = [side(r, s) for r in sub]
            print(f"{s:13s} {sum(x['correct'] for x in rs)/len(rs):6.3f} "
                  f"{sum(x['service_reduction'] for x in rs):5d} "
                  f"{sum(bool(x['observed_path_blocked']) for x in rs):7d} "
                  f"{sum(x['legit_flows_cut'] for x in rs):4d}")

    print("\n== McNemar vs BIZM (paired per decision) ==")
    for s in systems[:-1]:
        b = sum(1 for r in rows if side(r, "bizm")["correct"] and not side(r, s)["correct"])
        c = sum(1 for r in rows if not side(r, "bizm")["correct"] and side(r, s)["correct"])
        b, c, p = mcnemar(b, c)
        print(f"  bizm vs {s:13s} bizm-only-right={b:3d} other-only-right={c:3d} p={p:.4g}")

    wrong = [r for r in rows if not side(r, "bizm")["correct"]]
    print(f"\n== BIZM incorrect decisions: {len(wrong)} ==")
    for r in wrong[:25]:
        b = r["bizm"]
        print(f"  {r['case_id']:26s} {r['policy_verdict']:5s} exp={r['expected']:11s} "
              f"got={str(b['outcome']):9s} scope={b['scope']:5s} {b['reject'][:70]}")

    scopes = {}
    for r in rows:
        if r["bizm"]["contains"]:
            scopes[r["bizm"]["scope"]] = scopes.get(r["bizm"]["scope"], 0) + 1
    print(f"\nBIZM containment scopes chosen: {scopes}")


if __name__ == "__main__":
    args = sys.argv[1:] or sorted(glob.glob("results/matrix_sweep_*.json"))
    main([p for a in args for p in glob.glob(a)])
