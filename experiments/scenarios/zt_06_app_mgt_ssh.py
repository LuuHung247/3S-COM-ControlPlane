#!/usr/bin/env python3
"""eval_app_mgt_ssh.py — Cross-tier SSH lateral movement (SID 9000035)

Workload-to-workload SSH attempt: compromised APP tier probes SSH on
WEB:22 / DB:22. Only MGT zone may SSH into workloads — this is a textbook
T1021.004 (Remote Services: SSH) lateral-movement signal. P1 severity —
agent DROPs + flags source host.

Runs N independent trials via the shared eval_iid harness. Pass criterion:
agent emits DROP for src=10.2.100.10 → *:22, SF rule visible on LEAF.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_app_mgt_ssh"
eval_iid.EVAL_TITLE = "Lateral Movement · cross-tier SSH probe (SID 9000035)"
eval_iid._apply_preset("app-mgt-ssh")

if __name__ == "__main__":
    eval_iid.main()
