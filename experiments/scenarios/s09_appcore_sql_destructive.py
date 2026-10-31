#!/usr/bin/env python3
"""s09_appcore_sql_destructive.py — APP-CORE → DB-OLTP DROP TABLE (V2 SID 9000072).

Content-level (L7) attack. The connection APP-CORE → DB-OLTP is FULLY ALLOWED
by matrix (normal SQL queries flow this path). Only the payload distinguishes
attack from baseline: SID 9000072 pcre-matches `\b(DROP\s+TABLE|TRUNCATE|DELETE\s+FROM)\b`.

P1 — no log_only allowed. Losing a table = losing the product. Agent must DROP
src=10.2.100.10 → 10.1.200.10:5432 with TTL, regardless of the fact that the
connection 4-tuple is otherwise legitimate.

Tests:
  - Deep-packet content rule (vs purely zone/rate-based detection)
  - Agent reasoning over "connection allowed, payload destructive" gap
  - V2 content rule range (9000070-9000072)

Rule lands on LEAF-2 (APP-CORE owner).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_v2_appcore_sql_destructive"
eval_iid.EVAL_TITLE = "V2 · APP-CORE→DB-OLTP destructive SQL (SID 9000072)"
eval_iid._apply_preset("v2-appcore-sql-destructive")

if __name__ == "__main__":
    eval_iid.main()
