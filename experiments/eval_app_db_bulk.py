#!/usr/bin/env python3
"""eval_app_db_bulk.py — DB→APP large reply payload (SID 9000032)

ALLOW-path semantic anomaly: APP issues bulk SELECT / JOIN against DB,
db-mock emits reply >4KB. Suricata fires on `dsize:>4096` threshold,
indicating bulk extraction via the legitimate reply channel that LEAF
cannot inspect.

Runs N independent trials via the shared eval_iid harness. Pass criterion:
agent emits DROP for src=10.2.100.10 → 10.1.200.10:5432, SF rule visible
on LEAF.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_iid

eval_iid.EVAL_NAME  = "eval_app_db_bulk"
eval_iid.EVAL_TITLE = "ALLOW-path Semantic Anomaly · DB bulk reply (SID 9000032)"
eval_iid._apply_preset("app-db-bulk")

if __name__ == "__main__":
    eval_iid.main()
