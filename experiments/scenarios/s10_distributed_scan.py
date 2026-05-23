#!/usr/bin/env python3
"""eval_yates_distributed_scan.py — Yatesbury Distributed Port Scan.

2+ Alpine attackers each scan few ports across many targets (low-and-slow
stealth). Per-source signal is weak; detection requires aggregate graph
view across all sources.

Paper reference: NetVigil NSDI'24 Table 4 AUC 0.99 (NetVigil), 0.41
                 (Kitsune+), 0.40 (Whisper) — NetVigil's biggest win on
                 this scenario due to its graph reasoning.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_yates_distributed_scan"
eval_iid.EVAL_TITLE = "Yatesbury · Distributed Port Scan (recon, multi-source)"
eval_iid._apply_preset("yates-distributed-scan")

if __name__ == "__main__":
    eval_iid.main()
