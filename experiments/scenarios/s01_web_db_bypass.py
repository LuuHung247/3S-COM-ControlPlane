#!/usr/bin/env python3
"""s01_web_db_bypass.py — WEB → DB-OLTP microsegmentation bypass (V2 SID 9000001 + 9000012).

V2 DENY-cell baseline. Compromised WEB-1 (10.1.100.10) attempts direct PostgreSQL
on DB-OLTP-1 (10.1.200.10:5432), bypassing the mandatory APP-GW → APP-CORE chain
required by the 8×8 zone policy matrix. LEAF-1 default-deny drops the SYN at
iptables FORWARD; Suricata captures via passive mirror, fires SID 9000001
(specific WEB→DB) AND SID 9000012 (generic unauthorized DB) — defense-in-depth.

Agent must DROP src=10.1.100.10/32 → 10.1.200.10/32:5432 with TTL. SF zone-routes
the rule to LEAF-1 (owner of both WEB and DB-OLTP zones).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_web_db_bypass"
eval_iid.EVAL_TITLE = "V2 · WEB→DB-OLTP microsegmentation bypass (SID 9000001+9000012)"
eval_iid._apply_preset("v2-web-db-bypass")

if __name__ == "__main__":
    eval_iid.main()
