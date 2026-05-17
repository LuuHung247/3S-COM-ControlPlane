#!/usr/bin/env python3
"""eval_web_app_burst.py — WEB→APP rate burst (SID 9000030)

ALLOW-path behavioural anomaly: compromised WEB tier weaponises its
zt-web-app-allow grant by flooding APP:8080 with >200 SYN/min (baseline
~60/min). LEAF accepts the traffic; only the agent can detect+block.

Runs N independent trials via the shared eval_iid harness — same metrics,
same Excel output schema, same reset-between-runs guarantee. Pass criterion:
agent emits DROP for src=10.1.100.10 → 10.2.100.10:8080, SF rule visible
on LEAF.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_web_app_burst"
eval_iid.EVAL_TITLE = "ALLOW-path Volumetric Anomaly · WEB→APP burst (SID 9000030)"
eval_iid._apply_preset("web-app-burst")

if __name__ == "__main__":
    eval_iid.main()
