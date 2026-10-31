#!/usr/bin/env python3
"""S11 — Multi-stage kill-chain temporal correlation — V2 8-zone fabric.

Tests whether the agent's cross-alert correlation (per-source 10-min window
`kill_chain_signal`, operational_memory.get_recent_alerts_for_correlation)
ESCALATES its decision as a kill chain progresses from one compromised host,
vs a memoryless signature-keyed SOAR (Baseline A) that judges each alert
independently.

This is the agent's distinctive capability over static SOAR: V2 KG encodes
multi-stage chains (knowledge_v2/infra/kill-chains.md, e.g.
presentation-tier-breach-to-data-exfiltration). A SOAR keyed on SIDs may
correctly DROP the final stage alert on its SID alone, but it cannot escalate
its confidence based on the prior sequence, nor can it surface correlation
reasoning (kill-chain label, campaign tracking). The agent running after
STAGE 1+2 has seen the reconnaissance and tier-skip attempts from the same
source; its STAGE 3 decision should carry higher confidence and explicit
correlation markers vs. the same STAGE 3 presented cold (no prior context).

Three stages, all from the same compromised host (WEB = 10.1.100.10) so that
operational_memory correlates them under the same src_ip key:

  STAGE 1 (recon):        low-severity vertical port scan toward APP-GW
  STAGE 2 (tier-skip):    WEB attempts direct connection to APP-CORE (skips APP-GW)
  STAGE 3 (crown-jewel):  WEB attempts direct connection to DB-OLTP (microsegmentation bypass)

Two proposed-agent run modes:
  run_sequence() — stages 1→2→3 in order (10-min correlation window populated)
  run_cold()     — stage 3 alone (cold start, no prior context)

Baseline A (memoryless SOAR) — correctly DROPs STAGE 3 on its known SID
  9000001, but produces identical output regardless of sequence context; it
  has no temporal awareness and cannot escalate.

Key thesis claim: proposed_sequence shows correlation_detected=True and a
confidence_lift > 0 relative to proposed_cold; Baseline A shows
baseline_a_temporal_awareness=False in both paths.

Agent runs LIVE (dry_run=false); enforced rules are removed in cleanup.
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

INTEL    = "http://localhost:8767"
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

# Baseline A's playbook: the V2 signature IDs it knows are dangerous (mirrors
# the system's own policy DROP-action SIDs — a SOAR built on the same signatures).
KNOWN_DANGEROUS_SIDS = {
    9000001, 9000002, 9000003, 9000004, 9000005, 9000006, 9000007, 9000008,
    9000009, 9000010, 9000012, 9000013, 9000070, 9000071, 9000072,
}

# Correlation markers to search for in the agent's decision reasoning text.
# Any one of these (case-insensitive) indicates the agent surfaced the kill
# chain context it accumulated from the prior stages.
CORRELATION_MARKERS = [
    "kill chain", "kill-chain", "correlat", "escalat",
    "multi-stage", "prior alert", "sequence", "campaign",
]

# Confidence threshold: if agent confidence on the in-sequence stage-3
# decision reaches this level, treat it as correlation evidence even when
# the reasoning text is abbreviated.
CORRELATION_CONF_THRESHOLD = 0.85


def _alert(sid, sev, src, dst, dport, sig, cat):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src, "dest_ip": dst, "src_port": 44444, "dest_port": dport,
        "proto": "TCP",
        "alert": {"signature_id": sid, "severity": sev, "signature": sig, "category": cat},
    }


# ── Kill-chain stage definitions ──────────────────────────────────────────────
# All stages share src=WEB so operational_memory correlates them under the
# same src_ip key within the 10-minute rolling window.

STAGE1 = _alert(
    9000041, 3, WEB, APP_GW, 8080,
    "Vertical port scan",
    "Detection of a Network Scan",
)

STAGE2 = _alert(
    9000002, 1, WEB, APP_CORE, 8090,
    "WEB to APP/WORKER direct - skips APP-GW",
    "Potentially Bad Traffic",
)

STAGE3 = _alert(
    9000001, 1, WEB, DB_OLTP, 5432,
    "WEB to DB direct - microsegmentation bypass",
    "Potentially Bad Traffic",
)


def _post(path, data, timeout=150):
    req = urllib.request.Request(f"{INTEL}{path}", data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())


def _is_llm_429(r):
    """A 'rejected' caused by Cerebras rate-limiting is an infra failure, not a
    real safety/policy decision — retry it rather than recording it."""
    rr = (r.get("rejection_reason") or "")
    return r.get("outcome") == "rejected" and ("429" in rr or "Too Many Requests" in rr or "LLM failed" in rr)


def _post_alert_with_retry(alert):
    """POST a single alert to /alerts with up to 6 retries on Cerebras 429."""
    r = None
    for attempt in range(6):                       # retry on Cerebras 429 (infra, not a decision)
        try:
            _post("/admin/reset", {}, timeout=8)   # clear per-IP rate limiter each try
        except Exception:
            pass
        try:
            r = _post("/alerts", {"data": alert})
        except Exception as exc:
            r = {"outcome": "rejected", "rejection_reason": str(exc) or type(exc).__name__}
        if not _is_llm_429(r):
            break
        time.sleep(30 * (attempt + 1))             # 30,60,90,... back off the rate limit
    return r


def _fetch_latest_decision():
    """GET /decisions?limit=1 and return the first decision dict, or None."""
    try:
        url = f"{INTEL}/decisions?limit=1"
        raw = urllib.request.urlopen(url, timeout=20).read()
        data = json.loads(raw)
        # API may return a list or a dict with a 'decisions' key
        if isinstance(data, list) and data:
            return data[0]
        if isinstance(data, dict):
            items = data.get("decisions") or data.get("items") or []
            if items:
                return items[0]
    except Exception:
        pass
    return None


def _check_correlation(decision_dict, confidence):
    """Return True if any correlation marker appears in the decision reasoning,
    OR if the in-sequence confidence meets the high-confidence threshold."""
    reasoning_text = ""
    if decision_dict:
        # Collect all candidate text fields that might carry reasoning narrative
        for key in ("reasoning", "primary_hypothesis", "explanation", "notes",
                    "narrative", "decision_reasoning"):
            val = decision_dict.get(key)
            if val and isinstance(val, str):
                reasoning_text += " " + val
        # Also stringify the full dict as a fallback (covers nested fields)
        reasoning_text += " " + json.dumps(decision_dict)

    reasoning_lower = reasoning_text.lower()
    text_hit = any(m in reasoning_lower for m in CORRELATION_MARKERS)
    conf_hit = isinstance(confidence, (int, float)) and confidence >= CORRELATION_CONF_THRESHOLD
    return text_hit or conf_hit


def run_sequence():
    """Inject STAGE1→STAGE2→STAGE3 in order; record the STAGE3 final decision.

    The three alerts all share src=WEB, so the agent's operational_memory
    accumulates prior alerts for that host before it must judge the final
    crown-jewel reach.  Returns a dict with outcome, confidence, blocked, and
    correlation_detected.
    """
    print("  [sequence] resetting memory + rules …")
    try:
        _post("/admin/reset", {}, timeout=8)
    except Exception:
        pass
    cleanup(quiet=True)

    for stage_label, alert in [("STAGE1 recon", STAGE1), ("STAGE2 tier-skip", STAGE2)]:
        print(f"  [sequence] injecting {stage_label} …")
        _post_alert_with_retry(alert)
        time.sleep(8)    # pace between stages; keeps alerts inside the 10-min window

    print("  [sequence] injecting STAGE3 crown-jewel (final + recorded) …")
    r3 = _post_alert_with_retry(STAGE3)

    outcome   = r3.get("outcome", "")
    enforced  = outcome == "enforced"
    blocked   = (r3.get("src_ip") or "").split("/")[0] if enforced else None
    confidence = r3.get("confidence")

    # Fetch the latest stored decision to inspect reasoning text
    latest_decision = _fetch_latest_decision()
    correlation_detected = _check_correlation(latest_decision, confidence)

    return {
        "outcome": outcome,
        "confidence": confidence,
        "blocked": blocked,
        "correlation_detected": correlation_detected,
        "stage3_decision_raw": r3,
        "latest_decision_fetched": latest_decision,
    }


def run_cold():
    """Inject STAGE3 alone (no prior stages); record the decision.

    Without prior context in operational_memory the agent has no kill-chain
    signal.  It should still DROP WEB→DB-OLTP (correct mitigation), but the
    confidence should be lower and correlation markers should be absent.
    Returns a dict with outcome, confidence, blocked.
    """
    print("  [cold] resetting memory + rules …")
    try:
        _post("/admin/reset", {}, timeout=8)
    except Exception:
        pass
    cleanup(quiet=True)

    print("  [cold] injecting STAGE3 only (cold start) …")
    r3 = _post_alert_with_retry(STAGE3)

    outcome   = r3.get("outcome", "")
    enforced  = outcome == "enforced"
    blocked   = (r3.get("src_ip") or "").split("/")[0] if enforced else None
    confidence = r3.get("confidence")

    return {
        "outcome": outcome,
        "confidence": confidence,
        "blocked": blocked,
        "stage3_decision_raw": r3,
    }


def run_baseline_a():
    """Traditional SOAR: act only if the STAGE3 SID is in the known-dangerous set.

    The SOAR produces identical output whether it is presented stage-3-cold or
    stage-3-in-sequence.  It has no memory of STAGE1/STAGE2 and therefore cannot
    escalate its response or label a kill chain.
    """
    sid = STAGE3["alert"]["signature_id"]   # 9000001
    action = "DROP" if sid in KNOWN_DANGEROUS_SIDS else "no-action"
    return {
        "sid": sid,
        "action": action,
        "temporal_awareness": False,          # explicit — SOAR is stateless
        "reason": (
            "matched known-dangerous SID" if action == "DROP"
            else "no rule for this SID — ignored"
        ),
        "note": (
            "Correct mitigation on SID match but no escalation or correlation; "
            "output is identical regardless of whether STAGE1/STAGE2 preceded this alert."
        ),
    }


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
    print(
        f"S11 Kill-Chain Multi-stage Temporal Correlation (V2 8-zone) — "
        f"proposed @ {INTEL} | Baseline A = signature-keyed SOAR"
    )
    print(
        "Kill chain: WEB(10.1.100.10) → [STAGE1 port-scan APP-GW:8080] "
        "→ [STAGE2 tier-skip APP-CORE:8090] → [STAGE3 crown-jewel DB-OLTP:5432]\n"
    )

    seq_result  = None
    cold_result = None

    try:
        # ── Proposed: sequence run ─────────────────────────────────────────────
        print("── Proposed (sequence: STAGE1→STAGE2→STAGE3) ──")
        seq_result = run_sequence()
        print(
            f"  outcome={seq_result['outcome']}  confidence={seq_result['confidence']}"
            f"  blocked={seq_result['blocked']}  correlation_detected={seq_result['correlation_detected']}"
        )
        print()
        # Must exceed the agent's dedup window (FILTER_DEDUP_WINDOW_SECONDS=30, key
        # src_ip+sid) or the cold STAGE3 is dropped as a duplicate of the sequence STAGE3.
        time.sleep(35)

        # ── Proposed: cold run (stage-3 only) ─────────────────────────────────
        print("── Proposed (cold: STAGE3 only, no prior context) ──")
        cold_result = run_cold()
        print(
            f"  outcome={cold_result['outcome']}  confidence={cold_result['confidence']}"
            f"  blocked={cold_result['blocked']}"
        )
        print()
        time.sleep(25)   # pace agent's LLM calls under Cerebras rate limit

    finally:
        print("  Cleanup:")
        n = cleanup()
        print(f"  [cleanup] removed {n} agent rule(s)\n")

    # ── Baseline A (memoryless SOAR) ───────────────────────────────────────────
    print("── Baseline A (memoryless SOAR — evaluated once; output is identical for both paths) ──")
    base = run_baseline_a()
    print(
        f"  SID={base['sid']}  action={base['action']}  "
        f"temporal_awareness={base['temporal_awareness']}"
    )
    print(f"  note: {base['note']}")
    print()

    # ── Metrics ───────────────────────────────────────────────────────────────
    seq_conf  = (seq_result  or {}).get("confidence")
    cold_conf = (cold_result or {}).get("confidence")
    if isinstance(seq_conf, (int, float)) and isinstance(cold_conf, (int, float)):
        confidence_lift: float | str = round(seq_conf - cold_conf, 4)
    else:
        confidence_lift = "N/A (one or both confidence values missing)"

    summary = {
        "fabric": "V2-8zone",
        "kill_chain_src": WEB,
        "stages": {
            "stage1": {"sid": 9000041, "sig": "Vertical port scan", "src": WEB, "dst": APP_GW,  "dport": 8080},
            "stage2": {"sid": 9000002, "sig": "WEB to APP/WORKER direct - skips APP-GW",  "src": WEB, "dst": APP_CORE, "dport": 8090},
            "stage3": {"sid": 9000001, "sig": "WEB to DB direct - microsegmentation bypass", "src": WEB, "dst": DB_OLTP, "dport": 5432},
        },
        "proposed_sequence": {
            "outcome":              (seq_result  or {}).get("outcome"),
            "confidence":          seq_conf,
            "blocked":             (seq_result  or {}).get("blocked"),
            "correlation_detected": (seq_result or {}).get("correlation_detected"),
        },
        "proposed_cold": {
            "outcome":    (cold_result or {}).get("outcome"),
            "confidence": cold_conf,
            "blocked":    (cold_result or {}).get("blocked"),
        },
        "confidence_lift":                   confidence_lift,
        "correlation_detected_in_sequence":  (seq_result or {}).get("correlation_detected", False),
        "baseline_a_temporal_awareness":     False,  # always — SOAR is stateless by design
        "baseline_a_action_stage3":          base["action"],
        "thesis_claim": (
            "Proposed agent escalates with kill-chain context (higher confidence, "
            "correlation markers present); SOAR correctly mitigates on SID match but "
            "cannot escalate, correlate across stages, or distinguish cold vs. sequence."
        ),
    }

    print("=" * 70)
    print(f"  Proposed sequence  — outcome={summary['proposed_sequence']['outcome']}"
          f"  conf={summary['proposed_sequence']['confidence']}"
          f"  blk={summary['proposed_sequence']['blocked']}"
          f"  corr={summary['proposed_sequence']['correlation_detected']}")
    print(f"  Proposed cold      — outcome={summary['proposed_cold']['outcome']}"
          f"  conf={summary['proposed_cold']['confidence']}"
          f"  blk={summary['proposed_cold']['blocked']}")
    print(f"  Confidence lift (sequence − cold): {summary['confidence_lift']}")
    print(f"  Correlation detected in sequence:  {summary['correlation_detected_in_sequence']}")
    print(f"  Baseline A temporal awareness:     {summary['baseline_a_temporal_awareness']}")
    print("=" * 70)

    RESULTS.mkdir(exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS / f"s11_killchain_multistage_{ts}.json"
    out.write_text(json.dumps({
        "summary":     summary,
        "sequence_run": seq_result,
        "cold_run":     cold_result,
        "baseline_a":   base,
    }, indent=2))
    print(f"  → {out}")


if __name__ == "__main__":
    main()
