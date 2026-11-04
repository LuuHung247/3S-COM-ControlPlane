#!/usr/bin/env python3
"""E7: decision-plane throughput under an offered alert load (dry run, no rule pushed).

Open-loop load: alerts are sent at a constant offered rate lambda for D seconds regardless
of how fast the service answers, so a saturated decision plane shows as a growing response
time. Alerts carry covered signatures only: (signature, source zone, destination zone)
combinations that the deployed synthesized program decides, never abstains on, for every
history bucket, so the compiled-path load never reaches the model. Sources are drawn from
the unprotected hosts of the source zone.
  --runtime : the same harness for the runtime-only configuration (every alert takes a
              model call); each alert uses a fresh (source, signature) pair

Usage: intelligence-layer/.venv/bin/python compiled_policy/e7_load.py OUT.jsonl
       --rates 10 50 100 --duration 120 [--runtime]
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import random
import statistics as st
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

IL = Path(__file__).resolve().parents[2] / "intelligence-layer"
sys.path.insert(0, str(IL))
from src.compiler.dsl import Ensemble, Program  # noqa: E402
from src.compiler.kb import KBSnapshot  # noqa: E402
from src.compiler.verifier import HISTORY_BUCKETS, domain, realizable  # noqa: E402
from src.compiler.dsl import Features  # noqa: E402

INTEL = "http://localhost:8767"


def covered_combos(kb, prog):
    """(sid, sev, src_zone, dst_zone) decided for every history bucket, unprotected source."""
    seen = {}
    for f in domain(kb):
        if f.src_protected or f.sid == 0 or not realizable(kb, f) or f.verdict in ("EXTERNAL", "INTRA"):
            continue
        key = (f.sid, f.severity, f.src_zone, f.dst_zone)
        ok = prog.evaluate(f).action != "abstain"
        seen[key] = seen.get(key, True) and ok
    return [k for k, ok in seen.items() if ok]


def hosts(kb, zone):
    net = ipaddress.ip_network(kb.zones[zone]["cidr"], strict=False)
    return [str(h) for h in list(net.hosts())[1:] if not kb.is_protected(str(h))]


def make_alert(sid, sev, src, dst, msg):
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "alert",
            "src_ip": src, "src_port": random.randint(32768, 60999), "dest_ip": dst, "dest_port": 5432,
            "proto": "TCP", "alert": {"signature_id": sid, "severity": sev, "signature": msg,
                                      "category": "Potentially Bad Traffic"}}


async def run_rate(client, rate, duration, pick, out, guard=False):
    """guard: stop sending if any alert reaches the model (compiled phase must not)."""
    sent, tasks = 0, []
    abort = [False]
    t0 = time.monotonic()

    async def one(i, alert):
        ts = time.monotonic()
        try:
            r = await client.post(f"{INTEL}/alerts", json={"data": alert}, timeout=300)
            d = r.json()
            rec = {"i": i, "t_send": round(ts - t0, 3), "lat_s": round(time.monotonic() - ts, 4),
                   "outcome": d.get("outcome"), "path": d.get("decision_path"),
                   "agent_ms": d.get("latency_ms")}
        except Exception as exc:
            rec = {"i": i, "t_send": round(ts - t0, 3), "lat_s": round(time.monotonic() - ts, 4),
                   "outcome": "client_error", "error": str(exc)[:80]}
        rec["t_done"] = round(time.monotonic() - t0, 3)
        if guard and rec.get("path") == "runtime":
            abort[0] = True
        out.append(rec)

    while True:
        target = t0 + sent / rate
        now = time.monotonic()
        if target - t0 >= duration or abort[0]:
            break
        if target > now:
            await asyncio.sleep(target - now)
        tasks.append(asyncio.create_task(one(sent, pick())))
        sent += 1
    await asyncio.gather(*tasks)
    return sent


def summarize(rate, duration, recs):
    ok = [r for r in recs if r["outcome"] not in ("client_error", "filtered", "error")]
    lat = sorted(r["lat_s"] for r in ok)
    q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))] if lat else None
    done_in_window = sum(1 for r in ok if r["t_done"] <= duration)
    early = [r["lat_s"] for r in ok if r["t_send"] < duration / 4]
    late = [r["lat_s"] for r in ok if r["t_send"] >= 3 * duration / 4]
    paths = {}
    for r in recs:
        paths[f"{r.get('path')}:{r['outcome']}"] = paths.get(f"{r.get('path')}:{r['outcome']}", 0) + 1
    return {"offered_per_s": rate, "sent": len(recs), "decided": len(ok),
            "sustained_per_s": round(done_in_window / duration, 1),
            "lat_p50_ms": round(1000 * q(0.5), 1) if lat else None,
            "lat_p95_ms": round(1000 * q(0.95), 1) if lat else None,
            "lat_p99_ms": round(1000 * q(0.99), 1) if lat else None,
            "lat_first_quarter_med_ms": round(1000 * st.median(early), 1) if early else None,
            "lat_last_quarter_med_ms": round(1000 * st.median(late), 1) if late else None,
            "agent_ms_p50": (round(st.median([r["agent_ms"] for r in ok if r.get("agent_ms") is not None]), 2)
                             if ok else None),
            "paths": paths}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--rates", type=float, nargs="+", required=True)
    ap.add_argument("--duration", type=float, default=120)
    ap.add_argument("--runtime", action="store_true")
    a = ap.parse_args()
    kb = KBSnapshot.load(IL / "knowledge_v2")
    art = json.load(open(IL / "compiled" / "policy.json"))
    prog = (Ensemble([Program.from_json(x, kb.zone_names()) for x in art["ensemble"]])
            if art.get("ensemble") else Program.from_json(art["program"], kb.zone_names()))
    combos = covered_combos(kb, prog)
    pools = {z: hosts(kb, z) for z in kb.zone_names()}
    dsts = {z: [h for h in pools[z][:5]] for z in kb.zone_names()}
    print(f"covered combos: {len(combos)}", flush=True)
    rnd = random.Random(11)
    fresh = iter(range(10 ** 9))

    def pick():
        sid, sev, sz, dz = rnd.choice(combos)
        if a.runtime:                      # a fresh source per alert: no dedup, no cache hit
            n = next(fresh)
            src = pools[sz][n % len(pools[sz])]
            sid = sid
        else:
            src = rnd.choice(pools[sz])
        return make_alert(sid, sev, src, rnd.choice(dsts[dz]), kb.sids[sid].msg)

    limits = httpx.Limits(max_connections=4000, max_keepalive_connections=4000)
    async with httpx.AsyncClient(limits=limits) as client:
        for rate in a.rates:
            await client.post(f"{INTEL}/admin/reset", json={})
            recs = []
            await run_rate(client, rate, a.duration, pick, recs, guard=not a.runtime)
            if any(r.get("path") == "runtime" for r in recs) and not a.runtime:
                print(json.dumps({"aborted": "runtime path reached in compiled phase", "rate": rate}), flush=True)
                break
            s = summarize(rate, a.duration, recs)
            s["config"] = "runtime_only" if a.runtime else "compiled"
            print(json.dumps(s), flush=True)
            with open(a.out, "a") as fh:
                fh.write(json.dumps({"summary": s, "records": recs}) + "\n")
            await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(main())
