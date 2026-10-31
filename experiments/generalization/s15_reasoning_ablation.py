#!/usr/bin/env python3
"""S15 — Reasoning-vs-Lookup Ablation (signature-hint ablation) — V2 8-zone fabric.

Answers the reviewer critique directly: "if the agent is handed a SID→action
mapping, how is it different from a rule-based SOAR?" The codebase *does* inject a
per-SID hint (severity, attack-type label, recommended action) into the decision
prompt for KNOWN signatures (see docs/agent_reasoning_vs_lookup_findings.md). This
experiment removes that hint and measures whether the agent still decides correctly.

Method: each malicious flow is presented at two hint levels —
  • known   : the real V2 SID (full SID→action hint in the prompt), and
  • unknown : an out-of-table SID (sid_context = "Unknown SID") + a *generic*
              signature message + severity drawn from the alert only,
so the agent must decide purely from the flow tuple + zone policy matrix +
baseline + topology (genuine reasoning), with no handed action.

Two systems are compared:
  • Proposed   — the live agent (POST {INTEL}/alerts).
  • Baseline A — a Traditional SOAR: a fixed playbook keyed on Suricata signature
                 IDs. If the alert's SID is in its known-dangerous set it issues a
                 DROP; otherwise it does nothing. (Pure-Python lookup, no model.)

Legitimate ALLOW-path flows are included at the unknown-SID level as controls: the
correct decision is *not* to DROP. The killer comparison is M1-unknown
(WEB→DB-OLTP, must DROP) vs L1-unknown (APP-CORE→DB-OLTP, must NOT DROP): identical
metadata (unknown SID, generic msg, same severity, SAME dst 10.1.200.10:5432) —
only the source zone differs — so a correct split can only come from policy
reasoning, not from any signature lookup.

Metric: Mitigation Success Rate on the malicious flows (correctly DROPped), plus
overall correct-decision rate including the legitimate controls.

V2 zone policy matrix (knowledge_v2/infra/policy-matrix.md):
  WEB→DB-OLTP DENY, WEB→APP-GW ALLOW, APP-GW→APP-CORE ALLOW, APP-GW→DB-OLTP DENY,
  APP-CORE→DB-OLTP ALLOW, APP-CORE→WEB DENY (reverse-tier lateral).

Agent runs LIVE (dry_run=false); enforced DROPs are removed in cleanup.
"""
from __future__ import annotations

import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = ROOT / "results"

INTEL = "http://localhost:8767"
IDS_AGENT = "http://localhost:8766"

# V2 8-zone fabric host IPs (primary host per zone)
WEB       = "10.1.100.10"
DB_OLTP   = "10.1.200.10"
APP_CORE  = "10.2.100.10"
MGT       = "10.2.50.10"
APP_GW    = "10.3.100.10"
DB_ANLT   = "10.3.200.10"
WORKER    = "10.4.100.10"
MON       = "10.4.200.10"

# Baseline A's playbook: the V2 signature IDs it knows are dangerous (mirrors the
# system's own policy DROP-action SIDs — a SOAR built on the same signatures).
KNOWN_DANGEROUS_SIDS = {
    9000001, 9000002, 9000003, 9000004, 9000005, 9000006, 9000007, 9000008,
    9000009, 9000010, 9000012, 9000013, 9000070, 9000071, 9000072,
}

GENERIC_MSG = "Generic protocol anomaly detected"
GENERIC_CAT = "Misc activity"


def _alert(sid, sev, src, dst, dport, sig, cat):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src, "dest_ip": dst, "src_port": 44444, "dest_port": dport,
        "proto": "TCP",
        "alert": {"signature_id": sid, "severity": sev, "signature": sig, "category": cat},
    }


# id, class, expected, true_src, hint, alert
CASES = [
    # ── malicious DENY-path flows — expected DROP ──
    # M1: WEB → DB-OLTP microsegmentation bypass (cell DENY)
    dict(id="M1-known",   cls="malicious", expected="DROP", true_src=WEB, hint="known V2 SID 9000001",
         alert=_alert(9000001, 1, WEB, DB_OLTP, 5432, "WEB to DB direct - microsegmentation bypass", "Potentially Bad Traffic")),
    dict(id="M1-unknown", cls="malicious", expected="DROP", true_src=WEB, hint="unknown SID + generic msg",
         alert=_alert(9000901, 2, WEB, DB_OLTP, 5432, GENERIC_MSG, GENERIC_CAT)),
    # M2: APP-GW → DB-OLTP tier-skip (cell DENY; APP-GW may only reach APP-CORE)
    dict(id="M2-known",   cls="malicious", expected="DROP", true_src=APP_GW, hint="known V2 SID 9000004",
         alert=_alert(9000004, 1, APP_GW, DB_OLTP, 5432, "APP-GW to DB direct - skips APP-CORE", "Potentially Bad Traffic")),
    dict(id="M2-unknown", cls="malicious", expected="DROP", true_src=APP_GW, hint="unknown SID + generic msg",
         alert=_alert(9000902, 2, APP_GW, DB_OLTP, 5432, GENERIC_MSG, GENERIC_CAT)),
    # M3: APP-CORE → WEB:22 reverse-tier lateral (cell DENY; business flow is one-way)
    dict(id="M3-known",   cls="malicious", expected="DROP", true_src=APP_CORE, hint="known V2 SID 9000006",
         alert=_alert(9000006, 2, APP_CORE, WEB, 22, "APP-CORE reverse call to WEB/GW - lateral movement", "Attempted Administrator Privilege Gain")),
    dict(id="M3-unknown", cls="malicious", expected="DROP", true_src=APP_CORE, hint="unknown SID + generic msg",
         alert=_alert(9000903, 2, APP_CORE, WEB, 22, GENERIC_MSG, GENERIC_CAT)),

    # ── legitimate ALLOW-path flows — expected NOT-DROP (control) ──
    # L1: APP-CORE → DB-OLTP (cell ALLOW). KILLER control vs M1-unknown: identical
    #     dst 10.1.200.10:5432 + identical generic metadata; only source zone differs.
    dict(id="L1-unknown", cls="legit", expected="log_only", true_src=APP_CORE, hint="unknown SID + generic msg (ALLOW path)",
         alert=_alert(9000904, 2, APP_CORE, DB_OLTP, 5432, GENERIC_MSG, GENERIC_CAT)),
    # L2: WEB → APP-GW (cell ALLOW — legitimate north-south ingress to gateway)
    dict(id="L2-unknown", cls="legit", expected="log_only", true_src=WEB, hint="unknown SID + generic msg (ALLOW path)",
         alert=_alert(9000905, 2, WEB, APP_GW, 8080, GENERIC_MSG, GENERIC_CAT)),
    # L3: APP-GW → APP-CORE (cell ALLOW — legitimate gateway→business-logic transit)
    dict(id="L3-unknown", cls="legit", expected="log_only", true_src=APP_GW, hint="unknown SID + generic msg (ALLOW path)",
         alert=_alert(9000906, 2, APP_GW, APP_CORE, 8090, GENERIC_MSG, GENERIC_CAT)),
]


def _post(path, data, timeout=150):
    req = urllib.request.Request(f"{INTEL}{path}", data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def _is_llm_429(r):
    """A 'rejected' caused by Cerebras rate-limiting is an infra failure, not a
    real safety/policy decision — retry it rather than recording it."""
    rr = (r.get("rejection_reason") or "")
    return r.get("outcome") == "rejected" and ("429" in rr or "Too Many Requests" in rr or "LLM failed" in rr)


def run_proposed(case):
    t0 = time.time()
    cleanup(quiet=True)                            # fresh deny-by-default per case (no leftover rule confound)
    r = None
    for attempt in range(6):                      # retry on Cerebras 429 (infra, not a decision)
        try:
            _post("/admin/reset", {}, timeout=8)   # clear per-IP rate limiter each try
        except Exception:
            pass
        try:
            r = _post("/alerts", {"data": case["alert"]})
        except Exception as exc:
            r = {"outcome": "rejected", "rejection_reason": str(exc) or type(exc).__name__}
        if not _is_llm_429(r):
            break
        time.sleep(30 * (attempt + 1))            # 30,60,90,... back off the rate limit
    outcome = r.get("outcome", "")
    enforced = outcome == "enforced"
    blocked = (r.get("src_ip") or "").split("/")[0] if enforced else None
    decision = "DROP" if enforced else "no-drop"
    if case["expected"] == "DROP":
        correct = enforced and blocked == case["true_src"]
    else:  # legit → correct iff NOT a DROP
        correct = not enforced
    return {"outcome": outcome, "decision": decision, "blocked": blocked,
            "confidence": r.get("confidence"), "correct": correct,
            "reject": (r.get("rejection_reason") or "")[:100],
            "latency_s": round(time.time() - t0, 2)}


def run_baseline_a(case):
    """Traditional SOAR: act only if the SID is a known dangerous signature."""
    sid = case["alert"]["alert"]["signature_id"]
    action = "DROP" if sid in KNOWN_DANGEROUS_SIDS else "no-action"
    if case["expected"] == "DROP":
        correct = action == "DROP"
    else:
        correct = action == "no-action"
    return {"sid": sid, "action": action, "correct": correct,
            "reason": "matched known-dangerous SID" if action == "DROP" else "no rule for this SID — ignored"}


def cleanup(quiet=False):
    try:
        data = json.loads(urllib.request.urlopen(f"{IDS_AGENT}/rules", timeout=8).read())
    except Exception as exc:
        if not quiet:
            print(f"  [cleanup] list failed: {exc}")
        return 0
    ids = []
    for ld in (data.get("leaves") or {}).values():
        for n in (ld.get("rules") or {}).get("notification", []):
            for u in n.get("update", []):
                v = u.get("val", {})
                if v.get("source") == "agent":
                    rid = v.get("rule-id") or v.get("rule_id")
                    if rid and rid not in ids:
                        ids.append(rid)
    removed = 0
    for rid in ids:
        try:
            urllib.request.urlopen(urllib.request.Request(f"{IDS_AGENT}/rules/{rid}", method="DELETE"), timeout=8)
            removed += 1
            if not quiet:
                print(f"  [cleanup] deleted {rid}")
        except Exception as exc:
            if not quiet:
                print(f"  [cleanup] failed {rid}: {exc}")
    return removed


def main():
    print(f"S15 Reasoning-vs-Lookup Ablation (V2 8-zone) — proposed @ {INTEL} | Baseline A = signature-keyed SOAR")
    print(f"Cases: {len(CASES)} ({sum(c['cls']=='malicious' for c in CASES)} malicious, "
          f"{sum(c['cls']=='legit' for c in CASES)} legit controls)\n")
    rows = []
    try:
        for c in CASES:
            prop = run_proposed(c)
            base = run_baseline_a(c)
            pc = "OK" if prop.get("correct") else "WRONG"
            bc = "OK" if base.get("correct") else "WRONG"
            print(f"  {c['id']:11} [{c['cls']:9} exp={c['expected']:8} | {c['hint']}]")
            print(f"      proposed : {prop.get('outcome','ERR'):9} blk={str(prop.get('blocked')):16} "
                  f"conf={prop.get('confidence')} -> {pc}")
            print(f"      baselineA: {base['action']:9} ({base['reason']}) -> {bc}")
            rows.append({**{k: c[k] for k in ("id", "cls", "expected", "hint", "true_src")},
                         "proposed": prop, "baseline_a": base})
            time.sleep(25)   # pace agent's GLM calls under Cerebras rate limit
    finally:
        print("\n  Cleanup:")
        n = cleanup()
        print(f"  [cleanup] removed {n} agent rule(s)\n")

    mal = [r for r in rows if r["cls"] == "malicious"]
    mal_unknown = [r for r in mal if "unknown" in r["id"]]
    def rate(rs, sys): return sum(r[sys]["correct"] for r in rs), len(rs)

    p_msr = rate(mal, "proposed"); b_msr = rate(mal, "baseline_a")
    p_msr_u = rate(mal_unknown, "proposed"); b_msr_u = rate(mal_unknown, "baseline_a")
    p_all = rate(rows, "proposed"); b_all = rate(rows, "baseline_a")

    summary = {
        "fabric": "V2-8zone",
        "n_cases": len(rows), "n_malicious": len(mal), "n_malicious_unknown": len(mal_unknown),
        "mitigation_success_proposed": f"{p_msr[0]}/{p_msr[1]}",
        "mitigation_success_baseline_a": f"{b_msr[0]}/{b_msr[1]}",
        "mitigation_success_unknown_proposed": f"{p_msr_u[0]}/{p_msr_u[1]}",
        "mitigation_success_unknown_baseline_a": f"{b_msr_u[0]}/{b_msr_u[1]}",
        "correct_decision_proposed": f"{p_all[0]}/{p_all[1]}",
        "correct_decision_baseline_a": f"{b_all[0]}/{b_all[1]}",
    }
    print("=" * 70)
    print(f"  Mitigation Success (all malicious)      proposed={summary['mitigation_success_proposed']}"
          f"   baselineA={summary['mitigation_success_baseline_a']}")
    print(f"  Mitigation Success (unknown-SID only)   proposed={summary['mitigation_success_unknown_proposed']}"
          f"   baselineA={summary['mitigation_success_unknown_baseline_a']}")
    print(f"  Correct decision (incl. legit controls) proposed={summary['correct_decision_proposed']}"
          f"   baselineA={summary['correct_decision_baseline_a']}")
    print("=" * 70)

    RESULTS.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS / f"s15_reasoning_ablation_{ts}.json"
    out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
    print(f"  → {out}")


if __name__ == "__main__":
    main()
