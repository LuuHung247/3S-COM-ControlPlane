#!/usr/bin/env python3
"""E7 (decision plane, horizontal): the compiled path in P independent processes that
share the testbed Redis, as P service workers would.

  open   : offered load lambda split evenly over P processes, open loop, D seconds
  closed : capacity; every process keeps C alerts in flight for D seconds
Each process loads and re-verifies the deployed program itself (CompiledPolicy) and runs
the per-alert steps of e7_inproc.decide_one. Redis database 9 is used and flushed.

Usage: intelligence-layer/.venv/bin/python compiled_policy/e7_scale.py OUT.jsonl
       open --rate 1000 --procs 8 --duration 120
       closed --procs 1 2 4 8 16 --concurrency 32 --duration 60
"""
from __future__ import annotations

import argparse
import asyncio
import json
import multiprocessing as mp
import random
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
IL = HERE.parents[1] / "intelligence-layer"
sys.path.insert(0, str(IL))
sys.path.insert(0, str(HERE))


def _worker(idx, mode, rate, concurrency, duration, barrier, outq):
    import e7_inproc as E
    from e7_load import covered_combos, hosts, make_alert
    from src.compiler.fast_path import CompiledPolicy
    from src.storage.redis import RedisStore

    async def run():
        cp = CompiledPolicy()
        await cp.load(str(IL / "compiled" / "policy.json"), str(IL / "knowledge_v2"))
        kb = cp._kb
        combos = covered_combos(kb, cp._decider)
        pools = {z: hosts(kb, z) for z in kb.zone_names()}
        rnd = random.Random(1000 + idx)

        def pick():
            sid, sev, sz, dz = rnd.choice(combos)
            return make_alert(sid, sev, rnd.choice(pools[sz]), rnd.choice(pools[dz][:5]), kb.sids[sid].msg)

        redis = RedisStore(E.REDIS)
        import redis.asyncio as aioredis          # bounded pool, as one service worker would hold
        redis._client = aioredis.Redis(connection_pool=aioredis.BlockingConnectionPool.from_url(
            E.REDIS, max_connections=64, timeout=None, decode_responses=True))
        await asyncio.get_running_loop().run_in_executor(None, barrier.wait)
        if mode == "open":
            sent, recs, depth = await E.run_rate(cp, redis, rate, duration, pick)
            res = {"sent": sent, "lat": [r[1] for r in recs], "hist": [r[3] for r in recs],
                   "done": sum(1 for r in recs if r[0] + r[1] <= duration),
                   "late": [r[1] for r in recs if r[0] >= 0.75 * duration],
                   "max_queue": max(d for _, d in depth), "abstained": sum(r[4] == "abstain" for r in recs)}
        else:
            lat, t0 = [], time.monotonic()

            async def loop():
                while time.monotonic() - t0 < duration:
                    dt, _, _ = await E.decide_one(cp, redis, pick())
                    lat.append(dt)
            await asyncio.gather(*(loop() for _ in range(concurrency)))
            res = {"done": len(lat), "lat": lat}
        await redis.close()
        return res

    outq.put(asyncio.run(run()))


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))] if xs else None


def launch(mode, procs, rate, concurrency, duration):
    ctx = mp.get_context("spawn")
    barrier, outq = ctx.Barrier(procs), ctx.Queue()
    ps = [ctx.Process(target=_worker, args=(i, mode, rate / procs if rate else 0, concurrency, duration,
                                            barrier, outq)) for i in range(procs)]
    for p in ps:
        p.start()
    res = [outq.get() for _ in ps]
    for p in ps:
        p.join()
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("mode", choices=["open", "closed"])
    ap.add_argument("--rate", type=float, nargs="*", default=[])
    ap.add_argument("--procs", type=int, nargs="+", default=[1])
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--duration", type=float, default=120)
    a = ap.parse_args()
    import redis as _r
    flush = lambda: _r.Redis.from_url("redis://localhost:6379/9").flushdb()
    runs = [(p, r) for p in a.procs for r in (a.rate or [0])]
    try:
        for procs, rate in runs:
            flush()
            res = launch(a.mode, procs, rate, a.concurrency, a.duration)
            lat = [x for r in res for x in r["lat"]]
            s = {"mode": a.mode, "procs": procs, "offered_per_s": rate or None,
                 "sustained_per_s": round(sum(r["done"] for r in res) / a.duration, 1),
                 "lat_p50_ms": round(1000 * q(lat, .5), 2), "lat_p95_ms": round(1000 * q(lat, .95), 2),
                 "lat_p99_ms": round(1000 * q(lat, .99), 2)}
            if a.mode == "open":
                late = [x for r in res for x in r["late"]]
                hist = [x for r in res for x in r["hist"]]
                s.update(lat_last_quarter_p50_ms=round(1000 * q(late, .5), 2),
                         history_p50_ms=round(1000 * q(hist, .5), 3), history_p99_ms=round(1000 * q(hist, .99), 3),
                         max_queue_per_proc=max(r["max_queue"] for r in res),
                         abstained=sum(r["abstained"] for r in res))
            else:
                s["concurrency_per_proc"] = a.concurrency
            print(json.dumps(s), flush=True)
            with open(a.out, "a") as fh:
                fh.write(json.dumps(s) + "\n")
    finally:
        flush()


if __name__ == "__main__":
    main()
