#!/usr/bin/env python3
"""Full-matrix sweep: response correctness AND measured exposure reduction vs collateral.

For every case produced by build_cases.py the agent is given one alert and its decision
is scored two ways:
  (1) containment correctness against the mechanically derived ground truth;
  (2) the effect of the rule it chose on the lateral-movement exposure of the compromised
      source, and the legitimate baseline flows that rule cuts.

The same two measurements are computed for deterministic reference systems on the same
alerts, so every system is placed on the same containment/collateral axes:
  static-only   the deployed Zero Trust matrix with no runtime response
  soar-host     signature playbook; contains by isolating the source host
  fixed-flow    matrix lookup; always contains at flow scope
  graph-rule    matrix lookup plus the graph scope criteria (BIZM without the LLM)

Usage:
  intelligence-layer/.venv/bin/python matrix_sweep/sweep_eval.py [--repeats N] [--only ID,ID]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / "intelligence-layer"))
sys.path.insert(0, str(HERE.parent))
from build_cases import build  # noqa: E402
from src.core import exposure, graph_analytics  # noqa: E402
from src.core.policy import _ALLOW_PATH_ANOMALY_SIDS, check_policy  # noqa: E402
from src.agent.safety.guardrails import is_protected_ip  # noqa: E402

INTEL = "http://localhost:8767"
IDS_AGENT = "http://localhost:8766"
RESULTS = HERE.parents[1] / "results"
SOAR_PLAYBOOK = {9000001, 9000002, 9000003, 9000004, 9000005, 9000006, 9000007, 9000008,
                 9000009, 9000010, 9000012, 9000013, 9000070, 9000071, 9000072}


def _post(path, data, timeout=150):
    req = urllib.request.Request(f"{INTEL}{path}", data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def _rules():
    try:
        d = json.loads(urllib.request.urlopen(f"{IDS_AGENT}/rules", timeout=10).read())
    except Exception:
        return []
    return [u.get("val", {}) for ld in (d.get("leaves") or {}).values()
            for n in (ld.get("rules") or {}).get("notification", []) for u in n.get("update", [])
            if u.get("val", {}).get("source") == "agent"]


def cleanup():
    for v in _rules():
        rid = v.get("rule-id")
        if rid:
            try:
                urllib.request.urlopen(urllib.request.Request(
                    f"{IDS_AGENT}/rules/{rid}", method="DELETE"), timeout=10)
            except Exception:
                pass


# Volumetric signatures assert a rate, so the alert must carry the flow counters that
# justify it; without them the case asks for a decision on an unsupported claim.
VOLUMETRIC_SIDS = {9000050, 9000051, 9000052}


def alert_of(c: dict) -> dict:
    a = {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "alert",
         "src_ip": c["src_ip"], "dest_ip": c["dst_ip"], "src_port": 46000,
         "dest_port": c["dst_port"], "proto": "TCP",
         "alert": {"signature_id": c["sid"], "severity": c["severity"],
                   "signature": c["signature"], "category": "Potentially Bad Traffic"}}
    if c["sid"] in VOLUMETRIC_SIDS:
        a["flow"] = {"pkts_toserver": 4200, "pkts_toclient": 0,
                     "bytes_toserver": 252000, "bytes_toclient": 0,
                     "start": a["timestamp"]}
    return a


# ── deterministic reference systems ──────────────────────────────────────────
def ref_decisions(c: dict) -> dict[str, tuple[bool, str]]:
    """system -> (contains, scope)."""
    src, dst, port, sid = c["src_ip"], c["dst_ip"], c["dst_port"], c["sid"]
    protected = is_protected_ip(src)
    denied = check_policy(c["src_zone"], c["dst_zone"]) == "DENY"
    severe = c["severity"] <= 2
    # matrix-based admissibility, shared by fixed-flow and graph-rule
    matrix_contains = (not protected) and severe and (denied or sid in _ALLOW_PATH_ANOMALY_SIDS)
    soar = (not protected) and sid in SOAR_PLAYBOOK
    sig = graph_analytics.escalation_signals(src, dst, port, [])
    gscope = ("host" if (sig.get("pivot") == "yes" or int(sig.get("distinct_targets") or 0) >= 2)
              and sig.get("crown_jewel_path_open_under_flow_scope") == "yes"
              else "pair" if int(sig.get("ports_on_this_target") or 0) >= 2 else "flow")
    return {"static_only": (False, "none"), "soar_host": (soar, "host"),
            "fixed_flow": (matrix_contains, "flow"), "graph_rule": (matrix_contains, gscope)}


def effect(c: dict, contains: bool, scope: str) -> dict:
    if not contains or scope == "none":
        return {"contains": False, "scope": "none", "exposure_reduction": 0,
                "service_reduction": 0, "observed_path_blocked": False,
                "crown_jewel_contained": False, "crown_jewel_services_after": None,
                "legit_flows_cut": 0, "max_cut_criticality": "none"}
    e = exposure.containment_effect(
        c["src_ip"], "" if scope == "host" else c["dst_ip"],
        c["dst_port"] if scope == "flow" else 0, scope=scope)
    return {"contains": True, "scope": scope,
            "exposure_reduction": e.get("exposure_reduction", 0),
            "service_reduction": e.get("service_reduction", 0),
            "observed_path_blocked": e.get("observed_path_blocked", False),
            "crown_jewel_contained": e.get("crown_jewel_contained", False),
            "crown_jewel_services_after": e.get("crown_jewel_services_after"),
            "legit_flows_cut": e.get("legit_flows_cut", 0),
            "max_cut_criticality": e.get("max_cut_criticality", "none")}


def run_case(c: dict) -> dict:
    cleanup()
    try:
        _post("/admin/reset", {}, timeout=10)
    except Exception:
        pass
    t0 = time.time()
    try:
        d = _post("/alerts", {"data": alert_of(c)})
    except Exception as exc:
        d = {"outcome": "error", "rejection_reason": str(exc)}
    enforced = d.get("outcome") == "enforced"
    # The POST response omits dst_port, so the authoritative rule tuple (and therefore the
    # containment scope) is read back from the decision record.
    rec = {}
    if enforced:
        try:
            recs = json.loads(urllib.request.urlopen(f"{INTEL}/decisions?limit=10", timeout=15).read())
            rec = next((x for x in recs if x.get("id") == d.get("id")), recs[0] if recs else {})
        except Exception:
            rec = {}
    src_ip = rec.get("src_ip") or d.get("src_ip") or ""
    dst_ip = rec.get("dst_ip") if rec else d.get("dst_ip")
    dst_port = int((rec.get("dst_port") if rec else d.get("dst_port")) or 0)
    scope = exposure.scope_of(src_ip, dst_ip or "", dst_port) if enforced else "none"
    row = {"case_id": c["case_id"], "policy_verdict": c["policy_verdict"], "sid": c["sid"],
           "severity": c["severity"], "expected": c["expected"],
           "src_zone": c["src_zone"], "dst_zone": c["dst_zone"],
           "latency_s": round(time.time() - t0, 2),
           "bizm": {"outcome": d.get("outcome"), "confidence": d.get("confidence"),
                    "blocked": src_ip.split("/")[0] if enforced else None,
                    "rule": {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port} if enforced else None,
                    "target_ok": (not enforced) or src_ip.split("/")[0] == c["src_ip"],
                    "reject": (d.get("rejection_reason") or "")[:100]},
           "systems": {k: effect(c, v[0], v[1]) for k, v in ref_decisions(c).items()}}
    row["bizm"].update(effect(c, enforced, scope))
    row["bizm"]["correct"] = row["bizm"]["contains"] == (c["expected"] == "contain")
    for k, v in row["systems"].items():
        v["correct"] = v["contains"] == (c["expected"] == "contain")
    cleanup()
    return row


def aggregate(rows: list[dict]) -> dict:
    systems = ["bizm"] + list(rows[0]["systems"]) if rows else []
    out = {}
    for s in systems:
        rs = [r["bizm"] if s == "bizm" else r["systems"][s] for r in rows]
        tp = sum(1 for r, x in zip(rows, rs) if r["expected"] == "contain" and x["contains"])
        fn = sum(1 for r, x in zip(rows, rs) if r["expected"] == "contain" and not x["contains"])
        fp = sum(1 for r, x in zip(rows, rs) if r["expected"] == "no_contain" and x["contains"])
        tn = sum(1 for r, x in zip(rows, rs) if r["expected"] == "no_contain" and not x["contains"])
        out[s] = {
            "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "accuracy": round((tp + tn) / len(rows), 4) if rows else None,
            "zone_exposure_reduction_total": sum(x["exposure_reduction"] for x in rs),
            "service_exposure_reduction_total": sum(x["service_reduction"] for x in rs),
            "observed_paths_blocked": sum(bool(x["observed_path_blocked"]) for x in rs),
            "crown_jewels_contained": sum(x["crown_jewel_contained"] for x in rs),
            "legit_flows_cut_total": sum(x["legit_flows_cut"] for x in rs),
            "critical_flows_cut": sum(1 for x in rs if x["max_cut_criticality"] == "critical"),
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    data = build()
    cases = data["cases"]
    if args.only:
        keep = set(args.only.split(","))
        cases = [c for c in cases if c["case_id"] in keep]

    rows = []
    for rep in range(1, args.repeats + 1):
        for i, c in enumerate(cases, 1):
            r = run_case(c)
            r["repeat"] = rep
            rows.append(r)
            b = r["bizm"]
            print(f"[{rep}/{args.repeats} {i:3d}/{len(cases)}] {c['case_id']:28s} "
                  f"{c['policy_verdict']:5s} exp={c['expected']:11s} bizm={b['outcome']:9s} "
                  f"scope={b['scope']:5s} {'OK' if b['correct'] else 'X '} "
                  f"Δzone={b['exposure_reduction']} Δsvc={b['service_reduction']} "
                  f"cut={b['legit_flows_cut']} {b['reject']}")

    summary = {"generated_at": datetime.now(timezone.utc).isoformat(),
               "n_cases": len(cases), "repeats": args.repeats, "n_decisions": len(rows),
               "detection_gaps": data["detection_gaps"],
               "static_configurations": exposure.configuration_table(),
               "systems": aggregate(rows),
               "by_verdict": {v: aggregate([r for r in rows if r["policy_verdict"] == v])
                              for v in ("DENY", "ALLOW")}}
    print(json.dumps(summary["systems"], indent=2))
    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / f"matrix_sweep_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2, default=str))
    print(f"saved {out}")


if __name__ == "__main__":
    main()
