#!/usr/bin/env python3
"""One line per system from evaluate.py JSON output."""
import json, sys
d = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else json.load(sys.stdin)
for k, v in d.items():
    if not isinstance(v, dict) or "coverage" not in v:
        continue
    print(f"{k:18s} cov={v['coverage']:.3f} accDec={v['accuracy_decided']:.4f} acc(abst=wrong)={v['accuracy_all_known_abstain_as_wrong']:.4f} "
          f"TP={v['TP']} FN={v['FN']} FP={v['FP']} abst={v['abstain']} unkDrop={v['unknown_auto_drop']} amb={v.get('ambiguous_actions')} ver={v.get('verified')}",
          list(v['errors_by_sid'].items())[:4])
