#!/usr/bin/env python3
"""s06_worker_reverse.py — WORKER → APP-GW:8080 reverse (V2 SID 9000008).

V2 NEW attacker zone — WORKER-1 (10.4.100.10) on LEAF-4 (V2-only host).

WORKER tier semantics: receives dispatch from APP-CORE, writes to DB-OLTP.
Outbound to APP-GW is reverse-tier lateral (worker should never initiate
calls to the gateway). Matrix: WORKER → APP-GW = DENY.

Tests:
  - V2 NEW zone (10.4.x) as attacker source
  - Reverse-tier semantic (similar to s05 but different src zone)
  - Cross-LEAF enforcement (LEAF-4 attacker, LEAF-3 victim, rule lands LEAF-4)
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_worker_reverse"
eval_iid.EVAL_TITLE = "V2 · WORKER→APP-GW reverse lateral (SID 9000008)"
eval_iid._apply_preset("v2-worker-reverse")

if __name__ == "__main__":
    eval_iid.main()
