#!/usr/bin/env python3
"""eval_web_db_lateral.py — WEB→DB direct microsegmentation bypass (SID 9000001).

DENY-path baseline: compromised WEB tier attempts direct PostgreSQL on DB tier,
bypassing the application layer required by zone policy. LEAF zt-default-drop
drops the SYN; Suricata captures via mirror, fires SID 9000001, agent reasons
+ pushes targeted DROP rule with TTL.

Pass criterion: agent emits DROP for src=10.1.100.10 → 10.1.200.10:5432, SF
rule visible on LEAF FORWARD chain.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_web_db_lateral"
eval_iid.EVAL_TITLE = "DENY-path · WEB→DB microsegmentation bypass (SID 9000001)"
eval_iid._apply_preset("web-db-lateral")

if __name__ == "__main__":
    eval_iid.main()
