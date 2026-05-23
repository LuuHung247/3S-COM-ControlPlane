#!/usr/bin/env python3
"""eval_app_db_burst.py — APP→DB rate burst (SID 9000031)

ALLOW-path behavioural anomaly: compromised APP tier abuses its
zt-app-db-allow grant with >100 SYN/min (baseline ~2/min). LEAF accepts
the flow as legitimate application-to-database traffic; the SID fires on
behavioural threshold. Demonstrates the core thesis claim — agent must
override static ALLOW when behavioural signal indicates exfiltration probe.

Runs N independent trials via the shared eval_iid harness. Pass criterion:
agent emits DROP for src=10.2.100.10 → 10.1.200.10:5432, SF rule visible
on LEAF.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_app_db_burst"
eval_iid.EVAL_TITLE = "ALLOW-path Volumetric Anomaly · APP→DB burst (SID 9000031)"
eval_iid._apply_preset("app-db-burst")

if __name__ == "__main__":
    eval_iid.main()
