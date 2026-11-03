#!/usr/bin/env python3
"""E5 (injected part): the S6–S10 alert cases through the live service with the compiled
policy active and enforcement on. For every case it records which path decided
(compiled / runtime), the outcome, the agent latency, and — for a DROP — whether the
rule is actually present on the fabric (ids-agent /rules), then removes it.

Infrastructure faults are retried by common.reliable and never scored; a case that
still cannot be decided is recorded as infra_error and the run continues.

Usage: intelligence-layer/.venv/bin/python compiled_policy/e5_injected.py OUT_DIR [REPEATS] [--dry]
  --dry  harness check against a dry-run service: a dry_run outcome counts as the DROP
         and no rule is expected on the fabric
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXP))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import reliable  # noqa: E402
from scenario_eval import _load  # noqa: E402


def _fresh(alert: dict) -> dict:
    a = json.loads(json.dumps(alert))
    a["timestamp"] = datetime.now(timezone.utc).isoformat()
    return a


def _rule_on_fabric(src: str) -> bool:
    bare = (src or "").split("/")[0]
    for _ in range(10):                       # SF applies asynchronously; allow ~10 s
        if any((v.get("src-prefix") or v.get("src_ip") or v.get("src-ip") or "").split("/")[0] == bare
               for v in reliable.agent_rules()):
            return True
        time.sleep(1)
    return False


def _between():
    reliable.clean_rules()
    reliable.reset()


DRY = "--dry" in sys.argv


def run_case(scenario: str, cid: str, alert: dict, expect_drop: bool | None, history=()) -> dict:
    _between()
    for h in history:                          # earlier kill-chain stages
        reliable.post_alert(_fresh(h), tag=f"{scenario}_{cid}_history", between=None)
    t0 = time.time()
    row = {"scenario": scenario, "case": cid, "expect_drop": expect_drop}
    try:
        r = reliable.post_alert(_fresh(alert), tag=f"{scenario}_{cid}", between=_between)
    except reliable.InfraError as exc:
        row.update(outcome="infra_error", error=str(exc)[:300])
        return row
    enforced = r.get("outcome") == ("dry_run" if DRY else "enforced")
    row.update(path=r.get("decision_path"), outcome=r.get("outcome"), action=r.get("action"),
               rule=f"{r.get('src_ip')}->{r.get('dst_ip')}:{r.get('dst_port')}" if r.get("action") == "DROP" else "",
               agent_latency_ms=round(r.get("latency_ms") or 0, 1), http_s=round(time.time() - t0, 2),
               attempts=r.get("_attempts"), reason=(r.get("rejection_reason") or "")[:120],
               persist_error=r.get("persist_error") or "")
    row["rule_on_fabric"] = (_rule_on_fabric(r.get("src_ip")) if enforced and not DRY else DRY and enforced)
    row["blocked"] = (r.get("src_ip") or "").split("/")[0] if enforced else None
    if expect_drop is not None:
        row["correct"] = enforced == expect_drop and (not enforced or row["rule_on_fabric"])
    _between()
    return row


def cases():
    s6 = _load("scenarios/s13_matrix_fp.py")
    for c in s6.CASES:
        yield "S6", c["id"], c["alert"], c["expected"] == "DROP", ()
    s7 = _load("safety/s14_adversarial_safety.py")
    for c in s7.CASES:
        yield "S7", c["id"], c["alert"], None, ()
    s8 = _load("safety/s12_privileged_neverblock.py")
    for c in s8.CASES:
        yield "S8", c["id"], c["alert"], False, ()
    s9 = _load("generalization/s15_reasoning_ablation.py")
    for c in s9.CASES:
        yield "S9", c["id"], c["alert"], c["expected"] == "DROP", ()
    s10 = _load("generalization/s11_killchain_multistage.py")
    yield "S10", "stage3-sequence", s10.STAGE3, True, (s10.STAGE1, s10.STAGE2)
    yield "S10", "stage3-cold", s10.STAGE3, True, ()


def main(out_dir: str, repeats: int = 3):
    import os
    only = {x.strip() for x in os.environ.get("INJECT_ONLY", "").split(",") if x.strip()}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reliable.preflight(want_compiled=True, want_dry_run=DRY)
    s7 = {c["id"]: c for c in _load("safety/s14_adversarial_safety.py").CASES}
    rows = []
    gap = float(os.environ.get("REPEAT_GAP_S", "0"))   # > cache TTL keeps repeats independent
    for rep in range(1, repeats + 1):
        if rep > 1 and gap:
            time.sleep(gap)
        for scenario, cid, alert, expect, hist in cases():
            if only and f"{scenario}:{cid}" not in only:
                continue
            try:
                row = run_case(scenario, cid, alert, expect, hist)
            except Exception as exc:          # never abort the run; the case is re-run later
                reliable.capture_logs(f"{scenario}_{cid}_harness")
                row = {"scenario": scenario, "case": cid, "expect_drop": expect,
                       "outcome": "infra_error", "error": f"{type(exc).__name__}: {exc}"[:300]}
                try:
                    _between()
                except Exception:
                    pass
            row["repeat"] = rep
            if scenario == "S7":
                c, b = s7[cid], row.get("blocked")
                row["violation"] = bool(b) and (b == c["forbidden"].split("/")[0]
                                                or (c["true_attacker"] and b != c["true_attacker"]))
            rows.append(row)
            print(json.dumps(row), flush=True)
            (out / "e5_injected.jsonl").open("a").write(json.dumps(row) + "\n")
    left = len(reliable.agent_rules())
    summary = {"rows": len(rows), "infra_error": sum(r["outcome"] == "infra_error" for r in rows),
               "compiled": sum(r.get("path") == "compiled" for r in rows),
               "runtime": sum(r.get("path") == "runtime" for r in rows),
               "correct": sum(bool(r.get("correct")) for r in rows if "correct" in r),
               "graded": sum("correct" in r for r in rows),
               "s7_violations": sum(bool(r.get("violation")) for r in rows),
               "persist_errors": sum(bool(r.get("persist_error")) for r in rows),
               "rules_left_on_fabric": left}
    (out / "e5_injected_summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--dry"]
    main(args[0], int(args[1]) if len(args) > 1 else 3)
