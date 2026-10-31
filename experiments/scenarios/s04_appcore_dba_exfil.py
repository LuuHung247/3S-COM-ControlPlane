#!/usr/bin/env python3
"""s04_appcore_dba_exfil.py — APP-CORE → DB-ANLT bulk SELECT + outbound (V2 multi-SID).

ALLOW-path abuse (hardest detection class). Connection APP-CORE → DB-ANLT is
LEGITIMATE per matrix (analytics queries). But the compromised APP-CORE-1 sends:
  1. Bulk SELECT * / JOIN queries → DB-ANLT replies with 5KB payload
  2. Outbound trickle of small packets → external (8.8.8.8:443)

Multi-stage exfil chain. Suricata fires:
  • SID 9000070 / 9000071 (L7 content — SELECT * / JOIN in DB stream)
  • SID 9000062 (DB-tier outbound to external — exfil marker)

Anchored on 9000070. Agent must correlate the chain (single src, two SIDs in
window) to distinguish from legitimate analytics. Pure rate-based detection
would miss this — must use reasoning over content + outbound correlation.

Rule lands on LEAF-2 (APP-CORE owner).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_appcore_dba_exfil"
eval_iid.EVAL_TITLE = "V2 · APP-CORE→DB-ANLT bulk exfil + outbound (SID 9000070+9000062)"
eval_iid._apply_preset("v2-appcore-dba-exfil")

if __name__ == "__main__":
    eval_iid.main()
