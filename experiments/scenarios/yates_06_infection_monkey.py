#!/usr/bin/env python3
"""eval_yates_infection_monkey.py — Yatesbury Infection Monkey (multi-stage).

Adversary chain: scan → SSH probe → lateral hop. Each stage low-anomaly
on its own — detection emerges from correlating multiple stages within
a short window.

Paper reference: NetVigil NSDI'24 Table 4 AUC 1.00 (NetVigil), 0.56
                 (Kitsune+), 0.44 (Whisper). Difficult category.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_yates_infection_monkey"
eval_iid.EVAL_TITLE = "Yatesbury · Infection Monkey (multi-stage lateral)"
eval_iid._apply_preset("yates-infection-monkey")

if __name__ == "__main__":
    eval_iid.main()
