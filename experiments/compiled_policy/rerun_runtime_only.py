#!/usr/bin/env python3
"""Re-run injected S6 cases in the runtime-only configuration (compiled policy off,
enforcement on) to replace runs of the 26/10 campaign lost to a technical fault.

Usage: intelligence-layer/.venv/bin/python compiled_policy/rerun_runtime_only.py OUT.jsonl CASE_ID [...]
The caller sets AGENT_DRY_RUN=false and leaves COMPILED_POLICY_ENABLED unset.
"""
import importlib.util
import json
import sys
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXP))
sys.path.insert(0, str(EXP / "compiled_policy"))
from common import reliable  # noqa: E402
import e5_injected  # noqa: E402


def main(out: str, ids: list[str]):
    reliable.preflight(want_compiled=False, want_dry_run=False)
    spec = importlib.util.spec_from_file_location("s6", EXP / "scenarios" / "s13_matrix_fp.py")
    s6 = importlib.util.module_from_spec(spec)
    argv, sys.argv = sys.argv, ["x"]
    spec.loader.exec_module(s6)
    sys.argv = argv
    with open(out, "a") as fh:
        for c in s6.CASES:
            if c["id"] not in ids:
                continue
            row = e5_injected.run_case("S6", c["id"], c["alert"], c["expected"] == "DROP")
            row["config"] = "runtime-only"
            fh.write(json.dumps(row) + "\n")
            print(json.dumps(row))
    print("rules left:", reliable.clean_rules())


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
