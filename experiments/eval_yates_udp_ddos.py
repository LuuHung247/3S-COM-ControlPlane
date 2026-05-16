#!/usr/bin/env python3
"""eval_yates_udp_ddos.py — Yatesbury UDP DDoS (multiple attackers).

UDP flood from multiple sources to single victim. No handshake, harder
to filter than SYN. Often reflective (DNS amplification family).

Paper reference: NetVigil NSDI'24 Table 4 AUC 1.00 (NetVigil), 0.95
                 (Kitsune+), 0.64 (Whisper).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_iid

eval_iid.EVAL_NAME  = "eval_yates_udp_ddos"
eval_iid.EVAL_TITLE = "Yatesbury · UDP DDoS (volumetric DoS)"
eval_iid._apply_preset("yates-udp-ddos")

if __name__ == "__main__":
    eval_iid.main()
