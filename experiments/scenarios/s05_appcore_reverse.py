#!/usr/bin/env python3
"""s05_appcore_reverse.py — APP-CORE → WEB:22 reverse lateral (V2 SID 9000006).

APP-CORE-1 (10.2.100.10) tries SSH to WEB-1 (10.1.100.10:22). Matrix says
APP → WEB = DENY because forward chain goes WEB→APP-GW→APP-CORE, never reverse.
SSH attempt from APP tier to web tier = lateral movement (likely credential
harvesting target).

Distinct from V1 because V2 separates APP-GW + APP-CORE: the reverse violation
now has a clear tier-direction semantics ("downstream tier calling upstream").

P2 (not P1) — single-pkt rule (no threshold). SID 9000006. Rule on LEAF-2.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_appcore_reverse"
eval_iid.EVAL_TITLE = "V2 · APP-CORE→WEB:22 reverse lateral (SID 9000006)"
eval_iid._apply_preset("v2-appcore-reverse")

if __name__ == "__main__":
    eval_iid.main()
