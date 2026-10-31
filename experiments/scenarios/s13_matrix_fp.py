#!/usr/bin/env python3
"""S13 — East-west DENY-matrix coverage + False-Positive boundary — V2 8-zone fabric.

Two goals:
  (1) Cover the V2 policy-violation SIDs not exercised by S01-S10 (9000003, 9000005,
      9000007, 9000011, 9000013) — each a distinct DENY-cell east-west threat the
      agent must DROP at the correct source.
  (2) A FP-control battery of legitimate ALLOW-path flows that fire alerts but are
      within baseline — the agent must NOT over-block them (expected log_only).
      Strengthens the thesis "respects legitimate traffic" claim beyond the single
      S10 case.

Compared against Baseline A (signature-keyed SOAR) to show the FP cost of blind
signature-DROP.

NOTE on FP exposure: this particular FP set uses SIDs 9000060/9000040/9000080 which
are NOT in Baseline A's KNOWN_DANGEROUS_SIDS playbook, so baseline does not generate
false positives on them — that is expected. The FP value of the proposed system shows
when a DENY-class SID fires on a flow the proposed agent recognizes (via policy/
baseline reasoning) as legitimate. Baseline A is kept here for completeness and
comparison of DENY-cell mitigation.

V2 policy matrix: see knowledge_v2/infra/policy-matrix.md (8x8).
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

INTEL     = "http://localhost:8767"
IDS_AGENT = "http://localhost:8766"

# V2 8-zone fabric host IPs (primary host per zone)
WEB      = "10.1.100.10"
DB_OLTP  = "10.1.200.10"
APP_CORE = "10.2.100.10"
MGT      = "10.2.50.10"
APP_GW   = "10.3.100.10"
DB_ANLT  = "10.3.200.10"
WORKER   = "10.4.100.10"
MON      = "10.4.200.10"

# Baseline A's playbook: the V2 signature IDs it knows are dangerous (mirrors the
# system's own policy DROP-action SIDs — a SOAR built on the same signatures).
KNOWN_DANGEROUS_SIDS = {
    9000001, 9000002, 9000003, 9000004, 9000005, 9000006, 9000007, 9000008,
    9000009, 9000010, 9000012, 9000013, 9000070, 9000071, 9000072,
}


def _alert(sid, sev, src, dst, dport, sig, cat):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src, "dest_ip": dst, "src_port": 44444, "dest_port": dport,
        "proto": "TCP",
        "alert": {"signature_id": sid, "severity": sev, "signature": sig, "category": cat},
    }


# id, class, expected, true_src, alert
CASES = [
    # ── DENY-cell threats — expected DROP ──

    # D1: WEB → MGT:22 — WEB zone has no path to the management plane;
    #     SID 9000003 not fired in S01-S10, fills a coverage gap.
    dict(id="D1-9000003", cls="malicious", expected="DROP", true_src=WEB,
         alert=_alert(9000003, 1, WEB, MGT, 22,
                      "WEB to MGT/MON - unauthorized", "Attempted Administrator Privilege Gain")),

    # D2: APP-GW → WORKER:8080 — gateway attempting to bypass APP-CORE tier and
    #     reach worker nodes directly; lateral movement via zone skip.
    dict(id="D2-9000005", cls="malicious", expected="DROP", true_src=APP_GW,
         alert=_alert(9000005, 1, APP_GW, WORKER, 8080,
                      "APP-GW to non-APP zone - lateral move", "Potentially Bad Traffic")),

    # D3: APP-CORE → MON:9090 — business-logic tier probing the monitoring plane;
    #     DENY in the V2 matrix (APP-CORE must not reach MGT/MON).
    dict(id="D3-9000007", cls="malicious", expected="DROP", true_src=APP_CORE,
         alert=_alert(9000007, 1, APP_CORE, MON, 9090,
                      "APP-CORE to MGT/MON - unauthorized", "Potentially Bad Traffic")),

    # D4: DB-OLTP → MGT:22 — data-tier host initiating outbound to management; the
    #     allowed flow is strictly inbound to DB-OLTP, not egress to control plane.
    dict(id="D4-9000011", cls="malicious", expected="DROP", true_src=DB_OLTP,
         alert=_alert(9000011, 1, DB_OLTP, MGT, 22,
                      "Inbound to MGT zone from non-control - unauthorized access",
                      "Potentially Bad Traffic")),

    # D5: WORKER → DB-ANLT:5432 — worker nodes may only talk to APP-CORE; direct
    #     DB-ANALYTICS access from WORKER is a DENY cell (data exfiltration path).
    dict(id="D5-9000013", cls="malicious", expected="DROP", true_src=WORKER,
         alert=_alert(9000013, 2, WORKER, DB_ANLT, 5432,
                      "WORKER to DB-ANALYTICS - only APP-CORE allowed",
                      "Potentially Bad Traffic")),

    # ── FP-boundary controls — legitimate ALLOW-path flows — expected log_only ──
    # FP1/FP3 previously used SID 9000060, which the V2 catalog defines as a C2
    # heartbeat (ALLOW-path override SID) — inconsistent with the 'legit' label.
    # Replaced with V2 recon SIDs (log_only, FP likelihood medium), like FP2.

    # FP1: APP-CORE → DB-OLTP:5432 — normal OLTP query path (cell ALLOW in V2 matrix);
    #      a low-severity decode alert fires but the flow is baseline-legitimate.
    dict(id="FP1-allow", cls="legit", expected="log_only", true_src=APP_CORE,
         alert=_alert(9000042, 2, APP_CORE, DB_OLTP, 5432,
                      "APP-CORE to DB-OLTP query volume", "Generic Protocol Command Decode")),

    # FP2: WEB → APP-GW:8080 — standard north-south ingress to the gateway zone
    #      (cell ALLOW); connection-rate alert is expected on high-traffic ingress.
    dict(id="FP2-allow", cls="legit", expected="log_only", true_src=WEB,
         alert=_alert(9000040, 2, WEB, APP_GW, 8080,
                      "Connection rate from WEB to gateway", "Misc activity")),

    # FP3: APP-CORE → WORKER:8080 — legitimate job dispatch from business logic to
    #      worker tier (cell ALLOW); misc activity alert is benign in this path.
    dict(id="FP3-allow", cls="legit", expected="log_only", true_src=APP_CORE,
         alert=_alert(9000041, 2, APP_CORE, WORKER, 8080,
                      "APP-CORE dispatch to worker", "Misc activity")),

    # FP4: MGT → APP-CORE:22 — management-zone admin SSH audit (cell ALLOW; MGT is the
    #      control plane and is explicitly allowed to reach all zones); P4 / baseline.
    dict(id="FP4-baseline", cls="legit", expected="log_only", true_src=MGT,
         alert=_alert(9000080, 2, MGT, APP_CORE, 22,
                      "Management zone access", "Misc activity")),
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
    cleanup(quiet=True)                             # fresh deny-by-default per case (no leftover rule confound)
    r = None
    for attempt in range(6):                       # retry on Cerebras 429 (infra, not a decision)
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
        time.sleep(30 * (attempt + 1))             # 30,60,90,... back off the rate limit
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
    """Traditional SOAR: act only if the SID is a known dangerous signature.

    For the DENY-cell threats (D1-D5) the SIDs are in KNOWN_DANGEROUS_SIDS, so
    baseline correctly DROPs them.  For the FP controls (SIDs 9000060/9000040/9000080)
    the SIDs are NOT in the playbook, so baseline takes no action — which is the
    correct outcome for those flows.  This means this FP battery does not expose
    false-positive cost in Baseline A; see module docstring for the explanation.
    """
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
    n_mal  = sum(c["cls"] == "malicious" for c in CASES)
    n_legit = sum(c["cls"] == "legit"    for c in CASES)
    print(f"S13 DENY-matrix coverage + FP boundary (V2 8-zone) — proposed @ {INTEL} | Baseline A = signature-keyed SOAR")
    print(f"Cases: {len(CASES)} ({n_mal} DENY-cell threats, {n_legit} FP-boundary controls)\n")

    rows = []
    try:
        for c in CASES:
            prop = run_proposed(c)
            base = run_baseline_a(c)
            pc = "OK" if prop.get("correct") else "WRONG"
            bc = "OK" if base.get("correct") else "WRONG"
            sid = c["alert"]["alert"]["signature_id"]
            print(f"  {c['id']:13} [{c['cls']:9} exp={c['expected']:8} sid={sid}]")
            print(f"      proposed : {prop.get('outcome','ERR'):9} blk={str(prop.get('blocked')):16} "
                  f"conf={prop.get('confidence')} -> {pc}")
            print(f"      baselineA: {base['action']:9} ({base['reason']}) -> {bc}")
            rows.append({**{k: c[k] for k in ("id", "cls", "expected", "true_src")},
                         "sid": sid,
                         "proposed": prop, "baseline_a": base})
            time.sleep(25)   # pace agent's LLM calls under Cerebras rate limit
    finally:
        print("\n  Cleanup:")
        n = cleanup()
        print(f"  [cleanup] removed {n} agent rule(s)\n")

    mal_rows   = [r for r in rows if r["cls"] == "malicious"]
    legit_rows = [r for r in rows if r["cls"] == "legit"]

    def rate(rs, sys):
        return sum(r[sys]["correct"] for r in rs), len(rs)

    # ── proposed metrics ──
    p_deny  = rate(mal_rows,   "proposed")
    p_fp    = sum(not r["proposed"]["correct"] for r in legit_rows)   # FP count (should be 0)
    p_fp_r  = p_fp / len(legit_rows) if legit_rows else 0.0
    p_all   = rate(rows,       "proposed")

    # ── baseline A metrics ──
    b_deny  = rate(mal_rows,   "baseline_a")
    b_fp    = sum(not r["baseline_a"]["correct"] for r in legit_rows)
    b_fp_r  = b_fp / len(legit_rows) if legit_rows else 0.0
    b_all   = rate(rows,       "baseline_a")

    summary = {
        "fabric": "V2-8zone",
        "n_cases": len(rows),
        "n_malicious": len(mal_rows),
        "n_legit": len(legit_rows),
        # core thesis metrics
        "deny_matrix_mitigation_proposed":  f"{p_deny[0]}/{p_deny[1]}",
        "deny_matrix_mitigation_baseline_a": f"{b_deny[0]}/{b_deny[1]}",
        "fp_rate_proposed":  round(p_fp_r, 4),   # target 0.0
        "fp_rate_baseline_a": round(b_fp_r, 4),
        "correct_decision_proposed":  f"{p_all[0]}/{p_all[1]}",
        "correct_decision_baseline_a": f"{b_all[0]}/{b_all[1]}",
    }

    print("=" * 70)
    print(f"  DENY-matrix mitigation        proposed={summary['deny_matrix_mitigation_proposed']}"
          f"   baselineA={summary['deny_matrix_mitigation_baseline_a']}")
    print(f"  FP rate (legit over-blocked)  proposed={summary['fp_rate_proposed']:.4f}"
          f"   baselineA={summary['fp_rate_baseline_a']:.4f}  (target 0.0)")
    print(f"  Correct decision (all cases)  proposed={summary['correct_decision_proposed']}"
          f"   baselineA={summary['correct_decision_baseline_a']}")
    print("=" * 70)

    RESULTS.mkdir(exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS / f"s13_matrix_fp_{ts}.json"
    out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
    print(f"  → {out}")


if __name__ == "__main__":
    main()
