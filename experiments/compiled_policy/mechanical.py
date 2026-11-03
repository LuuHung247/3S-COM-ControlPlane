#!/usr/bin/env python3
"""E3: a mechanical compiler that reads only the structured fields of the catalog.

It sees each signature's severity and detection logic (hence the zone pairs it fires on),
the policy matrix, the zones and the never-block set, but not the prose of the catalog,
where the documented response is written. Two variants:
  decide_all : DROP a P1/P2 alert from an unprotected in-fabric source on a denied pair,
               log everything else
  abstain    : as decide_all on denied pairs and on the protective cases, abstain where the
               structured fields do not determine the response (permitted, intra-zone and
               outbound pairs)
Scored with the same grader as RQ1 (evaluate.score).

Usage: intelligence-layer/.venv/bin/python compiled_policy/mechanical.py OUT.json KB_DIR [...]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import score  # noqa: E402
from src.compiler.kb import EXTERNAL, KBSnapshot  # noqa: E402


def mechanical(kb, f, abstain: bool) -> str:
    if f.sid == 0:
        return "abstain"
    if f.src_protected or f.src_zone == EXTERNAL or f.severity > 2:
        return "log_only"
    if f.verdict == "DENY":
        return "DROP"
    return "abstain" if abstain else "log_only"


def main(out, kb_dirs):
    res = {}
    for d in kb_dirs:
        kb = KBSnapshot.load(d)
        res[Path(d).name] = {"kb_digest": kb.digest,
                             "decide_all": score(kb, lambda f: mechanical(kb, f, False)),
                             "abstain": score(kb, lambda f: mechanical(kb, f, True))}
        for v in ("decide_all", "abstain"):
            r = res[Path(d).name][v]
            print(Path(d).name, v, "acc", r["accuracy_decided"], "cov", r["coverage"],
                  "FN", r["FN"], "FP", r["FP"], flush=True)
    Path(out).write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
