#!/usr/bin/env python3
"""eval_yates_syn_flood_dos.py — Yatesbury SYN Flood DoS (single attacker).

APP host floods DB:5432 with TCP SYN (no ACK). High rate, half-open
connections exhaust victim's connection table.

Paper reference: NetVigil NSDI'24 Table 3 / Table 4
                 AUC 1.00 (NetVigil), 0.93 (Kitsune+), 0.76 (Whisper).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_iid

eval_iid.EVAL_NAME  = "eval_yates_syn_flood_dos"
eval_iid.EVAL_TITLE = "Yatesbury · SYN Flood DoS (DoS)"
eval_iid._apply_preset("yates-syn-flood-dos")

if __name__ == "__main__":
    eval_iid.main()
