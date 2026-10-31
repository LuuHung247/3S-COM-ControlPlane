#!/usr/bin/env python3
"""s02_web_gw_skip.py — WEB → APP-CORE skip APP-GW (V2 SID 9000002).

Compromised WEB-1 (10.1.100.10) tries to call APP-CORE-1 (10.2.100.10:8090)
directly, bypassing the mandatory APP-GW (10.3.100.10) transit tier. The 8×8
matrix encodes WEB → only APP-GW as ALLOW; WEB → APP-CORE = DENY.

This is the V2 "gateway bypass" pattern — distinct from S1 (DB bypass) because
APP-CORE is one tier deeper than APP-GW. Tests whether the agent recognizes
*tier-skip* violations, not just lateral-to-DB.

Rule lands on LEAF-1 (WEB tier ownership). Fires only 9000002 (single SID —
this cell has no generic backup SID).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_web_gw_skip"
eval_iid.EVAL_TITLE = "V2 · WEB→APP-CORE skip APP-GW gateway (SID 9000002)"
eval_iid._apply_preset("v2-web-gw-skip")

if __name__ == "__main__":
    eval_iid.main()
