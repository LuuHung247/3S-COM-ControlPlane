#!/usr/bin/env python3
"""eval_db_exfil.py — DB initiating outbound connection (SID 9000002)

DENY-path violation: DB host attempts outbound to internet (10.1.200.10 →
8.8.8.8:443). Per policy matrix, DB never initiates outbound — this is
a textbook T1041 (Exfiltration Over C2 Channel) signal indicating either
compromise or misconfiguration.

LEAF zt-default-drop already blocks this; the agent provides the audit
trail + cross-leaf consistency by pushing an explicit DROP rule + MITRE
mapping. Severity P1.

Runs N independent trials via the shared eval_iid harness. Pass criterion:
agent emits DROP for src=10.1.200.10, SF rule visible on LEAF.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_iid

eval_iid.EVAL_NAME  = "eval_db_exfil"
eval_iid.EVAL_TITLE = "DENY-path Audit · DB outbound exfiltration (SID 9000002)"
eval_iid._apply_preset("db-exfil")

if __name__ == "__main__":
    eval_iid.main()
