#!/usr/bin/env python3
"""eval_yates_vertical_scan.py — Yatesbury Vertical Port Scan.

Single attacker (APP) scans many ports of a single victim (DB).
Maps to threat-patterns.md C1 vertical_port_scan / LLaMA SUSPECT_scan.

Paper reference: NetVigil NSDI'24 Table 3, AUC 0.98 (NetVigil)
                                            0.93 (Kitsune+)
                                            0.90 (Whisper)
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_yates_vertical_scan"
eval_iid.EVAL_TITLE = "Yatesbury · Vertical Port Scan (recon, ALLOW-path)"
eval_iid._apply_preset("yates-vertical-scan")

if __name__ == "__main__":
    eval_iid.main()
