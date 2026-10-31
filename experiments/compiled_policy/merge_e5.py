#!/usr/bin/env python3
"""Merge E5 re-runs into the main campaign: each row the main run could not produce for a
technical reason (IDS raised no alert; provider/harness fault) is replaced, in place, by its
re-run, marked rerun=<source dir>. Originals are left untouched; output goes to e5_final/."""
import glob, json, shutil, sys
from pathlib import Path

R = Path(__file__).resolve().parents[1] / "results"
MAIN, OUT = R / "e5_20261027_0656", R / "e5_final"
RERUNS = [R / "e5_rerun_20261027_0856", R / "e5_rerun2_20261027_0900"]

OUT.mkdir(exist_ok=True)
(OUT / "real_traffic").mkdir(exist_ok=True)
# live: replace runs with alert_count_p1 == 0 by re-run runs of the same scenario
live_re = {}
for d in RERUNS:
    for f in glob.glob(str(d / "real_traffic" / "*.json")):
        name = Path(f).name.split("eval_v2_")[1].rsplit("_2026", 1)[0]
        live_re.setdefault(name, []).extend((d.name, r) for r in json.load(open(f)))
for f in glob.glob(str(MAIN / "real_traffic" / "*.json")):
    name = Path(f).name.split("eval_v2_")[1].rsplit("_2026", 1)[0]
    runs = json.load(open(f))
    for i, r in enumerate(runs):
        if r.get("outcome") == "none" and not r.get("alert_count_p1") and name != "baseline_mgt_mon_fp":
            src, new = live_re[name].pop(0)
            runs[i] = {**new, "run_num": r.get("run_num"), "rerun": src,
                       "replaced": {"reason": "IDS raised no alert", "started_at": r.get("started_at")}}
    json.dump(runs, open(OUT / "real_traffic" / Path(f).name, "w"), indent=1)
# injected: replace infra_error rows by the re-run of the same case
inj_re = {}
for d in RERUNS:
    p = d / "e5_injected.jsonl"
    if p.exists():
        for l in open(p):
            r = json.loads(l)
            if r["outcome"] != "infra_error":
                inj_re.setdefault((r["scenario"], r["case"]), []).append((d.name, r))
rows = []
for l in open(MAIN / "e5_injected.jsonl"):
    r = json.loads(l)
    if r["outcome"] == "infra_error":
        src, new = inj_re[(r["scenario"], r["case"])].pop(0)
        r = {**new, "repeat": r["repeat"], "rerun": src, "replaced": {"reason": r.get("error", "")[:160]}}
    rows.append(r)
with open(OUT / "e5_injected.jsonl", "w") as fh:
    for r in rows:
        fh.write(json.dumps(r) + "\n")
print("live replaced:", sum(1 for f in glob.glob(str(OUT / "real_traffic/*.json")) for r in json.load(open(f)) if r.get("rerun")),
      "injected replaced:", sum(bool(r.get("rerun")) for r in rows), "rows:", len(rows))
