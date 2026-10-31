#!/usr/bin/env python3
"""s08_dbanlt_pivot.py — DB-ANALYTICS init outbound (V2 SID 9000010 sink violation).

V2 NEW attacker zone — DB-ANLT-1 (10.3.200.10) on LEAF-3 (V2-only host).

DB-ANALYTICS is the strictest SINK in the matrix — it ONLY accepts replication
from DB-OLTP and scrape from MGT/MON. It MUST never initiate any flow. Any
outbound connection from 10.3.200.x is by definition a compromise indicator.

SID 9000010 fires on ANY outbound from DBA — even to internal zones (because
sink-role means zero-init). Tests:
  - V2 NEW zone (10.3.x DBA) as attacker
  - Sink-role enforcement (pure-receiver semantics)
  - Agent recognizing 'init by sink tier' = compromise regardless of destination

target_dst_ip in preset is 10.1.100.10 (WEB), but the controller probes multiple
destinations — agent should block src regardless of dst (sink violation).

Rule lands on LEAF-3.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_dbanlt_pivot"
eval_iid.EVAL_TITLE = "V2 · DB-ANALYTICS init outbound — sink violation (SID 9000010)"
eval_iid._apply_preset("v2-dbanlt-pivot")

if __name__ == "__main__":
    eval_iid.main()
