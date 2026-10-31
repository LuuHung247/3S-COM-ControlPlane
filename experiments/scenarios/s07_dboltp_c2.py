#!/usr/bin/env python3
"""s07_dboltp_c2.py — DB-OLTP → external C2 beacon (V2 SID 9000009 + 9000060 + 9000062).

DB tier is a PURE SINK in the matrix — should only receive writes from APP-CORE
+ WORKER and replicate INTO DB-ANLT. Outbound to !internal is always violation.

Compromised DB-OLTP-1 (10.1.200.10) periodically beacons to external
(8.8.8.8:443) with small jitter dsize<200 — classic C2 heartbeat pattern.

Fires 3 SIDs:
  • SID 9000009 — DB-OLTP outbound (sink-role violation)
  • SID 9000060 — beacon pattern (dsize<200, periodic threshold)
  • SID 9000062 — DB-tier exfil-to-external

3-SID correlation → agent must DROP with high confidence. Tests:
  - Sink-role semantics for DB tier
  - C2 pattern detection (paper-aligned, NetVigil benchmark equivalent)
  - Multi-SID per-flow correlation

Rule lands on LEAF-1.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_dboltp_c2"
eval_iid.EVAL_TITLE = "V2 · DB-OLTP→external C2 beacon (SID 9000009+9000060+9000062)"
eval_iid._apply_preset("v2-dboltp-c2")

if __name__ == "__main__":
    eval_iid.main()
