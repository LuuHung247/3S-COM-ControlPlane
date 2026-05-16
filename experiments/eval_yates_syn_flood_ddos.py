#!/usr/bin/env python3
"""eval_yates_syn_flood_ddos.py — Yatesbury SYN Flood DDoS (multiple attackers).

Coordinated SYN flood from APP + WEB hosts to a single DB victim. Aggregate
rate high but per-source may look legitimate — requires group-level
reasoning (count by_dst, sum aggregate rate).

Paper reference: NetVigil NSDI'24 Table 4 AUC 1.00 (NetVigil), 0.95
                 (Kitsune+), 0.91 (Whisper).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_iid

eval_iid.EVAL_NAME  = "eval_yates_syn_flood_ddos"
eval_iid.EVAL_TITLE = "Yatesbury · SYN Flood DDoS (coordinated DoS)"
eval_iid._apply_preset("yates-syn-flood-ddos")

if __name__ == "__main__":
    eval_iid.main()
