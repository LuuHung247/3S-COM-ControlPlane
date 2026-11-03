#!/usr/bin/env python3
"""S11: coordinated multi-source campaign against the global blast-radius limit.

n_s unprotected WEB sources violate the policy toward DB-OLTP (SID 9000001, P1, a denied
pair decided by the synthesized program) at the same time. As an attacking host keeps
triggering the IDS, every source re-raises its alert every PERIOD seconds until a rule
contains it; the 30 s alert dedup window of the gate applies as in production.
  direct : all n_s sources are real attackers
  decoy  : n_s spoofed addresses start first, and one further real source starts
           DECOY_LEAD seconds later; its containment delay t' is the cost of the attack
For every source the harness records when its first alert was sent and when a DROP for
it was enforced, and checks the rule on the fabric. No other address may be blocked.

Usage: intelligence-layer/.venv/bin/python compiled_policy/s11_campaign.py OUT_DIR
       --ns 3 5 8 12 --runs 5 [--decoy 12] [--decoy-runs 5] [--label default]
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXP))
from common import reliable  # noqa: E402

PERIOD = 10.0           # seconds between alerts of a still-uncontained source
HORIZON = 330.0         # give up on a source after this long
DECOY_LEAD = 5.0
DST, PORT, SID = "10.1.200.10", 5432, 9000001
REAL = [f"10.1.100.{20 + i}" for i in range(12)]
DECOYS = [f"10.1.100.{100 + i}" for i in range(12)]
REAL_AFTER_DECOY = "10.1.100.40"


def alert(src: str) -> dict:
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "alert",
            "src_ip": src, "src_port": 40000 + int(src.split(".")[-1]), "dest_ip": DST,
            "dest_port": PORT, "proto": "TCP",
            "alert": {"signature_id": SID, "signature": "ZT-V2 WEB to DB direct - microsegmentation bypass",
                      "category": "Potential Corporate Privacy Violation", "severity": 1, "action": "allowed"}}


def source_loop(src: str, t_start: float, delay: float, rec: dict, stop: threading.Event):
    time.sleep(delay)
    rec.update(src=src, first_alert_s=round(time.time() - t_start, 2), alerts=0, outcomes=[])
    while not stop.is_set() and time.time() - t_start < HORIZON:
        t_sent = time.time()
        try:
            r = reliable._req("POST", f"{reliable.INTEL}/alerts", {"data": alert(src)}, timeout=60)
        except Exception as exc:
            r = {"outcome": "error", "rejection_reason": str(exc)[:120]}
        rec["alerts"] += 1
        oc = r.get("outcome")
        rec["outcomes"].append([round(t_sent - t_start, 2), oc, (r.get("rejection_reason") or "")[:70],
                                r.get("decision_path")])
        if oc == "enforced" and (r.get("src_ip") or "").split("/")[0] == src:
            rec["contained_s"] = round(time.time() - t_start, 2)
            return
        stop.wait(max(0.0, PERIOD - (time.time() - t_sent)))


def one_run(sources: list[tuple[str, float, str]]) -> dict:
    reliable.clean_rules()
    reliable.reset()
    stop = threading.Event()
    t0 = time.time()
    recs = {s: {"role": role} for s, _, role in sources}
    threads = [threading.Thread(target=source_loop, args=(s, t0, d, recs[s], stop), daemon=True)
               for s, d, _ in sources]
    for th in threads:
        th.start()
    for th in threads:
        th.join(HORIZON + 70)
    stop.set()
    on_fabric = {(v.get("src-prefix") or v.get("src_ip") or "").split("/")[0] for v in reliable.agent_rules()}
    expected = {s for s, _, _ in sources}
    for s, r in recs.items():
        r["rule_on_fabric"] = s in on_fabric
    run = {"sources": list(recs.values()), "unexpected_blocked": sorted(on_fabric - expected),
           "wall_s": round(time.time() - t0, 1)}
    reliable.clean_rules()
    reliable.reset()
    return run


def summarize(run: dict, real_role: str) -> dict:
    real = [r for r in run["sources"] if r["role"] == real_role]
    t = [r.get("contained_s") for r in real]
    first = [r.get("contained_s") - r["first_alert_s"] for r in real if r.get("contained_s") is not None]
    return {"n": len(real), "contained": sum(x is not None for x in t),
            "contained_first_60s": sum(x is not None and x <= 60 for x in t),
            "all_contained_s": max(t) if all(x is not None for x in t) else None,
            "delay_after_first_alert_s": [round(x, 2) for x in first],
            "unexpected_blocked": len(run["unexpected_blocked"])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--ns", type=int, nargs="*", default=[3, 5, 8, 12])
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--decoy", type=int, default=12)
    ap.add_argument("--decoy-runs", type=int, default=5)
    ap.add_argument("--label", default="default")
    a = ap.parse_args()
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reliable.preflight(want_compiled=True, want_dry_run=False)
    log = (out / f"s11_{a.label}.jsonl").open("a")
    for ns in a.ns:
        for k in range(a.runs):
            run = one_run([(s, 0.0, "real") for s in REAL[:ns]])
            row = {"label": a.label, "variant": "direct", "ns": ns, "run": k + 1, **summarize(run, "real"), "raw": run}
            log.write(json.dumps(row) + "\n"); log.flush()
            print(json.dumps({x: row[x] for x in row if x != "raw"}), flush=True)
    for k in range(a.decoy_runs if a.decoy else 0):
        run = one_run([(s, 0.0, "decoy") for s in DECOYS[:a.decoy]] + [(REAL_AFTER_DECOY, DECOY_LEAD, "real")])
        dec = summarize(run, "decoy")
        real = [r for r in run["sources"] if r["role"] == "real"][0]
        row = {"label": a.label, "variant": "decoy", "ns": a.decoy, "run": k + 1, **dec,
               "real_delay_s": (round(real["contained_s"] - real["first_alert_s"], 2)
                                if real.get("contained_s") is not None else None), "raw": run}
        log.write(json.dumps(row) + "\n"); log.flush()
        print(json.dumps({x: row[x] for x in row if x != "raw"}), flush=True)
    left = reliable.clean_rules()
    print(json.dumps({"rules_removed_at_end": left}), flush=True)


if __name__ == "__main__":
    main()
