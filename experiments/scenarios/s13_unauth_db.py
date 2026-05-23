#!/usr/bin/env python3
"""eval_yates_unauth_db.py — Yatesbury Unauthorized Database Access.

WEB host connects directly to DB:5432 with stolen credentials, bypassing
the application tier required by zero-trust policy.

Maps to threat-patterns.md A1 cross_zone_violation_web_to_db (P1 severity).

Paper reference: NetVigil NSDI'24 Table 4 AUC 0.80 (NetVigil), 0.60
                 (Kitsune+), 0.72 (Whisper). Hard for anomaly-only
                 detectors; agent should classify P1 via policy matrix.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_yates_unauth_db"
eval_iid.EVAL_TITLE = "Yatesbury · Unauthorized DB Access (microseg bypass)"
eval_iid._apply_preset("yates-unauth-db")

if __name__ == "__main__":
    eval_iid.main()
