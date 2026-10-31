#!/usr/bin/env python3
"""s12_replay_eval.py — evaluate BIZM on public-dataset sessions replayed by the dataplane.

For each session in /3s-com/s12/manifest.csv (see S12-dataset-replay-spec.md):
  1. remove agent rules and reset agent state (rate limiter, flow markers, alert history);
  2. run `/3s-com/s12/replay.sh <session_id>` on the dataplane over SSH;
  3. collect the IDS alerts and the agent decisions inside the replay window;
  4. score the agent and the deterministic baselines against the dataset label.

A session counts as DROP for a system if it enforced at least one DROP whose source is the
session's lab source. Sessions that produced no IDS alert are reported as IDS misses and kept
out of the response metrics (BIZM acts after detection).

Usage:
  intelligence-layer/.venv/bin/python experiments/s12_replay/s12_replay_eval.py [--only ID,ID] [--limit N]
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1] / "baselines"))
import deterministic_baselines as B  # noqa: E402

INTEL = os.getenv("INTEL_URL", "http://localhost:8767")
IDS_AGENT = os.getenv("IDS_AGENT_URL", "http://localhost:8766")
IDS_API = os.getenv("IDS_API_URL", "http://10.10.6.238:8765")
DP_HOST = os.getenv("DP_HOST", "dis@10.10.6.238")
DP_PASS = os.getenv("DP_PASS", "")
S12_DIR = os.getenv("S12_DIR", "/3s-com/s12")
SETTLE_S = int(os.getenv("S12_SETTLE_S", "20"))
RESULTS = HERE.parents[1] / "results"
ATTACK_CATEGORIES = {"Web Application Attack", "Attempted Administrator Privilege Gain",
                     "Attempted User Privilege Gain", "A Network Trojan was detected",
                     "Executable code was detected", "Successful Administrator Privilege Gain"}


# ── I/O helpers ──────────────────────────────────────────────────────────────
def _ssh(cmd: str, timeout: int = 180) -> subprocess.CompletedProcess:
    base = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", DP_HOST, cmd]
    if DP_PASS:
        base = ["sshpass", "-p", DP_PASS] + base
    return subprocess.run(base, capture_output=True, text=True, timeout=timeout)


def _get(url: str, timeout: int = 15):
    return json.loads(urllib.request.urlopen(url, timeout=timeout).read())


def _post(url: str, data: dict, timeout: int = 15):
    req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def _ts(s: str) -> float:
    s = str(s or "").replace("Z", "+00:00")
    if len(s) > 5 and s[-5] in "+-" and s[-3] != ":":           # +0000 → +00:00
        s = s[:-2] + ":" + s[-2:]
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return 0.0


def cleanup_agent_rules() -> int:
    try:
        data = _get(f"{IDS_AGENT}/rules")
    except Exception:
        return 0
    ids = {u.get("val", {}).get("rule-id")
           for ld in (data.get("leaves") or {}).values()
           for n in (ld.get("rules") or {}).get("notification", [])
           for u in n.get("update", []) if u.get("val", {}).get("source") == "agent"}
    for rid in filter(None, ids):
        try:
            urllib.request.urlopen(urllib.request.Request(f"{IDS_AGENT}/rules/{rid}", method="DELETE"), timeout=10)
        except Exception:
            pass
    return len(ids)


def load_manifest() -> list[dict]:
    r = _ssh(f"cat {S12_DIR}/manifest.csv")
    if r.returncode != 0:
        sys.exit(f"cannot read manifest: {r.stderr.strip()}")
    return list(csv.DictReader(io.StringIO(r.stdout)))


# ── Scoring ──────────────────────────────────────────────────────────────────
def soar_et(alert: dict) -> str:
    a = alert.get("alert") or {}
    return "DROP" if int(a.get("severity") or 4) == 1 and a.get("category") in ATTACK_CATEGORIES else "log_only"


def session_alerts(row: dict, t0: float, t1: float) -> list[dict]:
    try:
        data = _get(f"{IDS_API}/alerts")
    except Exception:
        return []
    src, dst = row["lab_src"], row["lab_dst"]
    return [a for a in data.get("alerts", [])
            if t0 - 2 <= _ts(a.get("timestamp")) <= t1 + SETTLE_S
            and {a.get("src_ip"), a.get("dest_ip")} == {src, dst}]


def session_decisions(row: dict, t0: float, t1: float) -> list[dict]:
    try:
        recs = _get(f"{INTEL}/decisions?limit=100")
    except Exception:
        return []
    return [d for d in recs if t0 - 2 <= _ts(d.get("created_at")) <= t1 + SETTLE_S + 30
            and d.get("alert_src_ip") in (row["lab_src"], row["lab_dst"])]


def run_session(row: dict) -> dict:
    cleanup_agent_rules()
    try:
        _post(f"{INTEL}/admin/reset", {}, timeout=10)
    except Exception:
        pass
    t0 = time.time()
    r = _ssh(f"{S12_DIR}/replay.sh {row['session_id']}", timeout=240)
    t1 = time.time()
    replay_ok = r.returncode == 0 and f"S12_DONE {row['session_id']}" in r.stdout
    time.sleep(SETTLE_S)

    alerts = session_alerts(row, t0, t1)
    decs = session_decisions(row, t0, t1)
    src = row["lab_src"]
    agent_drop = any(d.get("outcome") == "enforced" and (d.get("src_ip") or "").split("/")[0] == src
                     for d in decs)
    src_alerts = [a for a in alerts if a.get("src_ip") == src] or alerts
    base = {name: ("DROP" if any(fn(a) == "DROP" for a in src_alerts) else "log_only")
            for name, fn in (("baseline_c", B.baseline_c), ("baseline_d", B.baseline_d),
                             ("soar_et", soar_et))}
    out = {
        "session_id": row["session_id"], "label": row["label_binary"],
        "orig_category": row.get("orig_category"), "lab_path": row["lab_path"],
        "policy_verdict": row["policy_verdict"], "replay_ok": replay_ok,
        "n_alerts": len(alerts), "sids": sorted({(a.get("alert") or {}).get("signature_id") for a in alerts}),
        "agent": "DROP" if agent_drop else "log_only",
        "agent_outcomes": [d.get("outcome") for d in decs],
        "semantic_override": any("L3-SO" in json.dumps(d.get("safety_checks") or "") for d in decs),
        **base,
    }
    cleanup_agent_rules()
    return out


def confusion(rows: list[dict], system: str) -> dict:
    cm = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}
    for r in rows:
        drop = r[system] == "DROP"
        if r["label"] == "malicious":
            cm["TP" if drop else "FN"] += 1
        else:
            cm["FP" if drop else "TN"] += 1
    p = cm["TP"] / (cm["TP"] + cm["FP"]) if cm["TP"] + cm["FP"] else None
    t = cm["TP"] / (cm["TP"] + cm["FN"]) if cm["TP"] + cm["FN"] else None
    f = 2 * p * t / (p + t) if p and t else None
    fpr = cm["FP"] / (cm["FP"] + cm["TN"]) if cm["FP"] + cm["TN"] else None
    return {**cm, "precision": p, "tcr": t, "f1": f, "fpr": fpr}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    rows = load_manifest()
    if args.only:
        keep = set(args.only.split(","))
        rows = [r for r in rows if r["session_id"] in keep]
    if args.limit:
        rows = rows[: args.limit]

    results = []
    for i, row in enumerate(rows, 1):
        res = run_session(row)
        results.append(res)
        print(f"[{i}/{len(rows)}] {res['session_id']:18s} {res['label']:9s} {res['lab_path']:22s} "
              f"{res['policy_verdict']:5s} alerts={res['n_alerts']:3d} agent={res['agent']:8s} "
              f"C={res['baseline_c']:8s} D={res['baseline_d']:8s} SOAR={res['soar_et']:8s}"
              f"{' SO' if res['semantic_override'] else ''}{'' if res['replay_ok'] else ' REPLAY-FAIL'}")

    detected = [r for r in results if r["n_alerts"] > 0 and r["replay_ok"]]
    summary = {"sessions": len(results), "detected": len(detected),
               "ids_miss": sum(r["n_alerts"] == 0 for r in results),
               "replay_fail": sum(not r["replay_ok"] for r in results)}
    for scope in ("ALL", "ALLOW", "DENY"):
        sub = [r for r in detected if scope == "ALL" or r["policy_verdict"] == scope]
        summary[scope] = {s: confusion(sub, s) for s in ("agent", "baseline_c", "baseline_d", "soar_et")}
    print(json.dumps(summary, indent=2))
    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / f"s12_replay_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"summary": summary, "rows": results}, indent=2, default=str))
    print(f"saved {out}")


if __name__ == "__main__":
    main()
