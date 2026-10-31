#!/usr/bin/env python3
"""s16_soc_scope.py — SOC containment-scope selection with multi-hop graph context.

Measures what a deterministic allow/deny decision cannot: choosing HOW MUCH to isolate.
Every case is a short alert sequence injected at the agent interface (state reset between
cases, including per-source alert history). The final alert of each case is the decision
under test; an optional follow-up probe checks whether the chosen scope already contained
the attacker's next step.

Expected scope per case (labelled before running, rationale inline):
  SC1  APP-CORE destructive SQL to DB-OLTP           → flow  (host isolation cuts 7 legit flows,
                                                              2 critical; one tuple is the threat)
  SC2  APP-GW direct to DB-OLTP, single violation    → flow  (no pivot, no fan-out; host would cut
                                                              the critical WEB→APP-GW→APP-CORE chain)
  SC3  WORKER probes DB-ANALYTICS on 3 ports         → pair  (same target, several ports)
  SC4  APP-CORE alerts on 2 distinct DENY targets    → host  (spreading source, 1-hop crown-jewel
                                                              paths stay open under flow/pair)
  SC5  APP-GW pivot: targeted by WEB, then APP-GW→DB → host  (pivot chain, root cause WEB;
                                                              follow-up APP-GW→APP-CORE:22 must be
                                                              already contained)

Baselines (deterministic, computed on the same alerts):
  SOAR-host  playbook "DROP src_ip" → always host scope
  Rule-flow  Baseline-C style       → always flow scope
  Graph-rule Baseline-C+            → host if (pivot or >=2 distinct targets) and a crown-jewel
                                      path stays open under flow scope; pair if >=2 ports on one
                                      target; else flow
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / "intelligence-layer"))
from src.core import graph_analytics as g  # noqa: E402

INTEL = os.getenv("INTEL_URL", "http://localhost:8767")
IDS_AGENT = os.getenv("IDS_AGENT_URL", "http://localhost:8766")
RESULTS = HERE.parents[1] / "results"
DEDUP_GAP_S = 35          # > agent dedup window (30 s, key src+sid)
STEP_GAP_S = 8

WEB, APP_GW, APP_CORE = "10.1.100.10", "10.3.100.10", "10.2.100.10"
WORKER, DB_OLTP, DB_ANLT = "10.4.100.10", "10.1.200.10", "10.3.200.10"
MON, MGT = "10.4.200.10", "10.2.50.10"


def _alert(sid, sev, src, dst, dport, sig, cat="Potentially Bad Traffic"):
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "alert",
            "src_ip": src, "dest_ip": dst, "src_port": 44444, "dest_port": dport, "proto": "TCP",
            "alert": {"signature_id": sid, "severity": sev, "signature": sig, "category": cat}}


# Each step: (alert-factory, gap_before_s). Factories so timestamps are fresh at send time.
CASES = [
    dict(id="SC1-permitted-abuse", src=APP_CORE, expected="flow", steps=[
        (lambda: _alert(9000072, 1, APP_CORE, DB_OLTP, 5432, "Destructive SQL statement in DB stream",
                        "Attempted Application Attack"), 0)]),
    dict(id="SC2-single-violation", src=APP_GW, expected="flow", steps=[
        (lambda: _alert(9000004, 1, APP_GW, DB_OLTP, 5432, "APP-GW to DB direct - skips APP-CORE"), 0)]),
    dict(id="SC3-multiport-probe", src=WORKER, expected="pair", steps=[
        (lambda: _alert(9000013, 2, WORKER, DB_ANLT, 5432, "WORKER to DB-ANALYTICS - only APP-CORE allowed"), 0),
        (lambda: _alert(9000013, 2, WORKER, DB_ANLT, 22, "WORKER to DB-ANALYTICS - only APP-CORE allowed"), DEDUP_GAP_S),
        (lambda: _alert(9000013, 2, WORKER, DB_ANLT, 8082, "WORKER to DB-ANALYTICS - only APP-CORE allowed"), DEDUP_GAP_S)]),
    dict(id="SC4-fanout-spreading", src=APP_CORE, expected="host", steps=[
        (lambda: _alert(9000007, 2, APP_CORE, MON, 9090, "APP-CORE to MGT/MON - unauthorized"), 0),
        (lambda: _alert(9000011, 1, APP_CORE, MGT, 22, "Inbound to MGT zone from non-control - unauthorized access"), STEP_GAP_S)]),
    dict(id="SC5-pivot", src=APP_GW, expected="host", root=WEB, steps=[
        (lambda: _alert(9000042, 2, WEB, APP_GW, 8080, "TCP probe on commonly-exploited service ports",
                        "Detection of a Network Scan"), 0),
        (lambda: _alert(9000004, 1, APP_GW, DB_OLTP, 5432, "APP-GW to DB direct - skips APP-CORE"), STEP_GAP_S)],
         followup=lambda: _alert(9000006, 2, APP_GW, APP_CORE, 22, "Lateral SSH from gateway tier",
                                 "Attempted Administrator Privilege Gain")),
]


# HELD-OUT set — never used for prompt development; the only S11 numbers reported.
# Different hosts (secondary *.11 and WORKER), zones and SIDs from the dev set above.
WEB2, APPGW2, APPCORE2 = "10.1.100.11", "10.3.100.11", "10.2.100.11"
WORKER2, DBANLT2 = "10.4.100.11", "10.3.200.11"

CASES_HELDOUT = [
    # single denied-cell violation from a worker → flow
    dict(id="H1-single-lateral", src=WORKER2, expected="flow", steps=[
        (lambda: _alert(9000008, 1, WORKER2, APP_GW, 8080, "WORKER lateral move - only DB-OLTP allowed"), 0)]),
    # destructive content on a permitted worker→DB edge → flow (host cuts worker persistence)
    dict(id="H2-permitted-abuse", src=WORKER, expected="flow", steps=[
        (lambda: _alert(9000072, 1, WORKER, DB_OLTP, 5432, "Destructive SQL statement in DB stream",
                        "Attempted Application Attack"), 0)]),
    # gateway probes one DB on several ports → pair
    dict(id="H3-multiport-probe", src=APPGW2, expected="pair", steps=[
        (lambda: _alert(9000004, 1, APPGW2, DB_OLTP, 5432, "APP-GW to DB direct - skips APP-CORE"), 0),
        (lambda: _alert(9000004, 1, APPGW2, DB_OLTP, 22, "APP-GW to DB direct - skips APP-CORE"), DEDUP_GAP_S),
        (lambda: _alert(9000004, 1, APPGW2, DB_OLTP, 8090, "APP-GW to DB direct - skips APP-CORE"), DEDUP_GAP_S)]),
    # worker reaches two distinct denied targets, crown path (WORKER→DB-OLTP) open → host
    dict(id="H4-fanout-spreading", src=WORKER2, expected="host", steps=[
        (lambda: _alert(9000008, 1, WORKER2, APP_GW, 8080, "WORKER lateral move - only DB-OLTP allowed"), 0),
        (lambda: _alert(9000008, 1, WORKER2, WEB, 80, "WORKER lateral move - only DB-OLTP allowed"), DEDUP_GAP_S)]),
    # worker pivot: targeted by APP-CORE-2, then hits DB-ANALYTICS → host, root cause APP-CORE-2
    dict(id="H5-pivot", src=WORKER2, expected="host", root=APPCORE2, steps=[
        (lambda: _alert(9000042, 2, APPCORE2, WORKER2, 8082, "TCP probe on commonly-exploited service ports",
                        "Detection of a Network Scan"), 0),
        (lambda: _alert(9000013, 2, WORKER2, DB_ANLT, 5432, "WORKER to DB-ANALYTICS - only APP-CORE allowed"), STEP_GAP_S)],
         followup=lambda: _alert(9000013, 2, WORKER2, DB_ANLT, 22, "WORKER to DB-ANALYTICS - only APP-CORE allowed")),
    # sink-tier host alerts on two targets but has no permitted path to any crown jewel → flow
    dict(id="H6-fanout-sink", src=DBANLT2, expected="flow", steps=[
        (lambda: _alert(9000010, 1, DBANLT2, APP_CORE, 8090, "DB-ANALYTICS initiating outbound - sink role violated"), 0),
        (lambda: _alert(9000010, 1, DBANLT2, WORKER, 8082, "DB-ANALYTICS initiating outbound - sink role violated"), DEDUP_GAP_S)]),
]


def _post(path, data, timeout=150):
    req = urllib.request.Request(f"{INTEL}{path}", data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def _get(url, timeout=10):
    return json.loads(urllib.request.urlopen(url, timeout=timeout).read())


def cleanup():
    try:
        data = _get(f"{IDS_AGENT}/rules")
    except Exception:
        return
    for ld in (data.get("leaves") or {}).values():
        for n in (ld.get("rules") or {}).get("notification", []):
            for u in n.get("update", []):
                v = u.get("val", {})
                rid = v.get("rule-id") or v.get("rule_id")
                if v.get("source") == "agent" and rid:
                    try:
                        urllib.request.urlopen(urllib.request.Request(
                            f"{IDS_AGENT}/rules/{rid}", method="DELETE"), timeout=8)
                    except Exception:
                        pass


def _send(alert):
    for attempt in range(5):
        try:
            r = _post("/alerts", {"data": alert})
        except Exception as exc:
            r = {"outcome": "rejected", "rejection_reason": str(exc)}
        rr = r.get("rejection_reason") or ""
        if not (r.get("outcome") == "rejected" and ("429" in rr or "LLM failed" in rr)):
            return r
        time.sleep(20 * (attempt + 1))
    return r


def scope_of(dst_ip, dst_port):
    if not (dst_ip or "").split("/")[0]:
        return "host"
    return "pair" if not dst_port else "flow"


def collateral(src, final_alert, scope):
    opts = {o["scope"]: o for o in g.containment_options(src, final_alert["dest_ip"], final_alert["dest_port"])}
    o = opts.get(scope)
    return (o["n_cut"], o["max_cut_criticality"], len(o["crown_jewels_still_reachable"])) if o else (None, None, None)


def graph_rule_scope(case, alerts):
    src = case["src"]
    final = alerts[-1]
    piv = g.pivot_chain(src, alerts, now=time.time())
    targets = {a["dest_ip"] for a in alerts if a["src_ip"] == src}
    ports = {a["dest_port"] for a in alerts if a["src_ip"] == src and a["dest_ip"] == final["dest_ip"]}
    flow_opt = next(o for o in g.containment_options(src, final["dest_ip"], final["dest_port"]) if o["scope"] == "flow")
    if (piv["is_pivot"] or len(targets) >= 2) and flow_opt["crown_jewels_still_reachable"]:
        return "host"
    return "pair" if len(ports) >= 2 else "flow"


def run_case(case):
    cleanup()
    try:
        _post("/admin/reset", {}, timeout=8)
    except Exception:
        pass
    sent, responses = [], []
    for factory, gap in case["steps"]:
        if gap:
            time.sleep(gap)
        a = factory()
        sent.append(a)
        responses.append(_send(a))
    # Decision under test = the last ENFORCED decision of the case. A later step that
    # comes back 'suppressed' was already contained by that rule (proactive containment).
    enforced_resp = [r for r in responses if r.get("outcome") == "enforced"]
    d = enforced_resp[-1] if enforced_resp else (responses[-1] if responses else {})
    pre_contained = sum(r.get("outcome") == "suppressed" for r in responses)
    time.sleep(12)                                     # let Stage-2 trace land
    rec = {}
    try:
        recs = _get(f"{INTEL}/decisions?limit=10")
        rec = next((x for x in recs if x.get("id") == d.get("id")), recs[0] if recs else {})
    except Exception:
        pass
    enforced = d.get("outcome") == "enforced"
    scope = scope_of(rec.get("dst_ip") if rec else d.get("dst_ip"), rec.get("dst_port") if rec else d.get("dst_port")) if enforced else "none"
    n_cut, max_crit, jewels_open = collateral(case["src"], sent[-1], scope) if enforced else (None, None, None)
    trace = " ".join([*(rec.get("reasoning") or []), *(rec.get("follow_up_actions") or []),
                      rec.get("notification_body") or "", rec.get("notification_title") or ""]) if rec else ""
    root_named = (case.get("root") in trace) if case.get("root") else None
    follow = None
    if case.get("followup"):
        # Past the dedup window, so a suppressed follow-up means the installed rule
        # already covers it rather than the alert being discarded as a duplicate.
        time.sleep(DEDUP_GAP_S)
        f = _send(case["followup"]())
        follow = {"outcome": f.get("outcome"), "contained": f.get("outcome") == "suppressed"}
    gr = graph_rule_scope(case, sent)
    out = {
        "id": case["id"], "expected_scope": case["expected"],
        "proposed": {"outcome": d.get("outcome"), "scope": scope, "scope_correct": scope == case["expected"],
                     "blocked": (d.get("src_ip") or "").split("/")[0] if enforced else None,
                     "confidence": d.get("confidence"), "legit_flows_cut": n_cut,
                     "max_cut_criticality": max_crit, "crown_jewels_still_reachable": jewels_open,
                     "root_cause_named": root_named, "followup": follow,
                     "steps_pre_contained": pre_contained,
                     "reject": (d.get("rejection_reason") or "")[:120]},
        "baselines": {},
    }
    for name, sc in (("soar_host", "host"), ("rule_flow", "flow"), ("graph_rule", gr)):
        n, mc, jo = collateral(case["src"], sent[-1], sc)
        out["baselines"][name] = {"scope": sc, "scope_correct": sc == case["expected"],
                                  "legit_flows_cut": n, "crown_jewels_still_reachable": jo}
    cleanup()
    return out


def main():
    rows = []
    only = {x for x in os.getenv("S16_ONLY", "").split(",") if x}
    case_set = CASES_HELDOUT if os.getenv("S16_SET", "dev") == "heldout" else CASES
    for c in case_set:
        if only and not any(c["id"].startswith(o) for o in only):
            continue
        r = run_case(c)
        p = r["proposed"]
        print(f"{r['id']:22s} exp={r['expected_scope']:4s} got={p['scope']:4s} "
              f"{'OK' if p['scope_correct'] else 'X '} cut={p['legit_flows_cut']} "
              f"root={p['root_cause_named']} follow={p['followup']} {p['reject']}")
        rows.append(r)
    summ = {"n_cases": len(rows),
            "proposed_scope_correct": sum(r["proposed"]["scope_correct"] for r in rows)}
    for b in ("soar_host", "rule_flow", "graph_rule"):
        summ[f"{b}_scope_correct"] = sum(r["baselines"][b]["scope_correct"] for r in rows)
    print(json.dumps(summ))
    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / f"s16_soc_scope_{os.getenv('S16_SET', 'dev')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"summary": summ, "rows": rows}, indent=2, default=str))
    print(f"saved {out}")


if __name__ == "__main__":
    main()
