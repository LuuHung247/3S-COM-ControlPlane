#!/usr/bin/env python3
"""s10_baseline_mgt_mon_fp.py — Baseline MGT/MON cron — FALSE-POSITIVE CONTROL (V2 SID 9000080+9000081).

NOT AN ATTACK. This scenario verifies the agent does NOT push DROP rules in
response to legitimate baseline DCN traffic. Critical for thesis claim: "agent
does not over-block".

What happens:
  • MGT-1 (10.2.50.10) cron runs every 2 min — SSH audit to all hosts.
    Fires SID 9000080 (P4 threshold:limit 1/60s "MGT-initiated session").
  • MONITORING-1 (10.4.200.10) cron runs every 60s — scrape WEB/APP-GW/
    APP-CORE/WORKER/DB-OLTP/DB-ANLT. Fires SID 9000081 (P4 threshold:limit
    1/300s "MON aggregation").

Both alerts are P4 audit (not threats). Agent receives them, emits
outcome=log_only, and pushes NO rule. The MGT/MON CIDRs are encoded as
ADMIN-baseline in intelligence-layer/knowledge/infra/baselines.md +
severity-scoring.md so the LLM cannot misclassify.

Pass criterion (INVERTED — see runner.py:614 EXPECTED_OUTCOME=='log_only' branch):
  outcome == 'log_only'  AND  no agent rule pushed for attacker IP

No trigger script needed — passive observation. SCENARIO_TRIGGER is the noop
sentinel 'true' which the harness recognizes (no console_run executed).

Recommended DURATION_SECONDS ≥ 180 (give MGT 2-min cron at least one full cycle).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_baseline_mgt_mon_fp"
eval_iid.EVAL_TITLE = "V2 · Baseline MGT/MON cron — FP control (SID 9000080+9000081, MUST log_only)"
eval_iid._apply_preset("v2-baseline-mgt-mon-fp")

if __name__ == "__main__":
    eval_iid.main()
