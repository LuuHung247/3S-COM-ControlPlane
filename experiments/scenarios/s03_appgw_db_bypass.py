#!/usr/bin/env python3
"""s03_appgw_db_bypass.py — APP-GW → DB-OLTP direct (V2 SID 9000004 + 9000012).

V2 NEW attacker zone — APP-GW-1 (10.3.100.10) is a NEW V2-only host (LEAF-3).
This proves agent + SF can detect + respond to attacks originating from a tier
not present in V1 fabric.

APP-GW is the API-gateway tier — its only allowed downstream is APP-CORE. Going
direct to DB-OLTP (10.1.200.10:5432) bypasses APP-CORE's data access controls.
Defense-in-depth fires SID 9000004 (specific APP-GW→DB) + SID 9000012 (generic).

Rule lands on LEAF-3 (APP-GW + DB-ANLT owner). Tests cross-LEAF enforcement:
attack visible on LEAF-1 mirror (DB-OLTP side capture), agent makes decision,
SF zone-routes the DROP rule to LEAF-3 (where the attacker host lives).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_appgw_db_bypass"
eval_iid.EVAL_TITLE = "V2 · APP-GW→DB-OLTP skip APP-CORE (SID 9000004+9000012)"
eval_iid._apply_preset("v2-appgw-db-bypass")

if __name__ == "__main__":
    eval_iid.main()
