#!/usr/bin/env python3
"""eval_yates_c2_beacon.py — Yatesbury C&C Communication.

Compromised APP host periodically beacons to external (NAT2) server.
Small payload (heartbeat), regular cadence with low jitter (~30s ± 5s).
Blends with normal traffic shape → "difficult" category in paper.

Paper reference: NetVigil NSDI'24 Table 4 AUC 0.93 (NetVigil), 0.63
                 (Kitsune+), 0.50 (Whisper).
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_iid

eval_iid.EVAL_NAME  = "eval_yates_c2_beacon"
eval_iid.EVAL_TITLE = "Yatesbury · C&C Beacon (periodic outbound to attacker)"
eval_iid._apply_preset("yates-c2-beacon")

if __name__ == "__main__":
    eval_iid.main()
