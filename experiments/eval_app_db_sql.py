#!/usr/bin/env python3
"""eval_app_db_sql.py — Destructive SQL pattern (SID 9000033)

ALLOW-path content anomaly: APP→DB traffic contains DROP TABLE / TRUNCATE
fragments. Suricata content-match fires; this pattern is never produced by
the legitimate OLTP workload. Severity P1 — agent must DROP + escalate.

Runs N independent trials via the shared eval_iid harness. Pass criterion:
agent emits DROP for src=10.2.100.10 → 10.1.200.10:5432 with P1 TTL (3600s),
SF rule visible on LEAF.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_iid

eval_iid.EVAL_NAME  = "eval_app_db_sql"
eval_iid.EVAL_TITLE = "ALLOW-path Content Anomaly · destructive SQL (SID 9000033)"
eval_iid._apply_preset("app-db-sql")

if __name__ == "__main__":
    eval_iid.main()
