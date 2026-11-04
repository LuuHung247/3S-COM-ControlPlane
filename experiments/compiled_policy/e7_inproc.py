#!/usr/bin/env python3
"""E7 (decision plane): the compiled path of the service, in one process, under an
open-loop offered load.

Per alert, exactly the steps the agent runs on the compiled path before enforcement:
parse the alert, read the source's alert history from Redis, extract the features,
evaluate the deployed program (CompiledPolicy, re-verified at load), build the intent,
append the alert to the history, and run the L1-L6 validators. HTTP handling,
persistence, streaming, embedding and enforcement are excluded; dedup is bypassed.
Redis is the testbed instance, on a separate database that is flushed afterwards.

Usage: intelligence-layer/.venv/bin/python compiled_policy/e7_inproc.py OUT.jsonl
       --rates 10 50 100 500 1000 2000 --duration 120
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path

IL = Path(__file__).resolve().parents[2] / "intelligence-layer"
sys.path.insert(0, str(IL))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from e7_load import covered_combos, hosts, make_alert  # noqa: E402
from src.agent.safety.validators import validate_intent  # noqa: E402
from src.compiler.fast_path import CompiledPolicy  # noqa: E402
from src.models.alert import SuricataAlert  # noqa: E402
from src.storage.redis import RedisStore  # noqa: E402

REDIS = "redis://localhost:6379/9"          # not the agent's database 0


async def decide_one(cp: CompiledPolicy, redis: RedisStore, raw: dict) -> tuple[float, float, str]:
    t0 = time.perf_counter()
    alert = SuricataAlert.from_raw(raw)
    h0 = time.perf_counter()
    history = await redis.get_alert_history(alert.src_ip)
    h1 = time.perf_counter()
    out, feats = cp.decide(alert, history)
    action = out.action
    if action != "abstain":
        intent = cp.intent_for(alert, out, feats)
        await redis.push_alert_history(alert.src_ip, alert.raw)
        validate_intent(intent, sid=alert.sid, ttl_min=60, ttl_max=3600, alert_src_ip=alert.src_ip,
                        alert_dst_ip=alert.dest_ip, alert_severity=alert.severity, alert_initiator_ip="")
    return time.perf_counter() - t0, h1 - h0, action


async def run_rate(cp, redis, rate, duration, pick):
    recs, inflight, depth = [], [0], []
    t0 = time.monotonic()
    sent = 0

    async def one(raw):
        inflight[0] += 1
        ts = time.monotonic()
        dt, hist, action = await decide_one(cp, redis, raw)
        inflight[0] -= 1
        recs.append((ts - t0, time.monotonic() - ts, dt, hist, action))

    async def sampler():
        while time.monotonic() - t0 < duration + 5:
            depth.append((round(time.monotonic() - t0, 1), inflight[0]))
            await asyncio.sleep(1)

    samp = asyncio.create_task(sampler())
    tasks = []
    while True:
        target = t0 + sent / rate
        if target - t0 >= duration:
            break
        now = time.monotonic()
        if target > now:
            await asyncio.sleep(target - now)
        tasks.append(asyncio.create_task(one(pick())))
        sent += 1
    await asyncio.gather(*tasks)
    samp.cancel()
    return sent, recs, depth


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))] if xs else None


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--rates", type=float, nargs="+", required=True)
    ap.add_argument("--duration", type=float, default=120)
    a = ap.parse_args()
    cp = CompiledPolicy()
    await cp.load(str(IL / "compiled" / "policy.json"), str(IL / "knowledge_v2"))
    assert cp.active, cp.status
    kb = cp._kb
    combos = covered_combos(kb, cp._decider)
    pools = {z: hosts(kb, z) for z in kb.zone_names()}
    rnd = random.Random(5)

    def pick():
        sid, sev, sz, dz = rnd.choice(combos)
        return make_alert(sid, sev, rnd.choice(pools[sz]), rnd.choice(pools[dz][:5]), kb.sids[sid].msg)

    redis = RedisStore(REDIS)
    import redis.asyncio as aioredis              # bounded pool, as one service worker would hold
    redis._client = aioredis.Redis(connection_pool=aioredis.BlockingConnectionPool.from_url(
        REDIS, max_connections=64, timeout=None, decode_responses=True))
    try:
        for rate in a.rates:
            await redis.client.flushdb()
            sent, recs, depth = await run_rate(cp, redis, rate, a.duration, pick)
            done = [r for r in recs if r[0] + r[1] <= a.duration]
            lat = [r[1] for r in recs]
            late = [r[1] for r in recs if r[0] >= 0.75 * a.duration]
            s = {"offered_per_s": rate, "sent": sent, "sustained_per_s": round(len(done) / a.duration, 1),
                 "lat_p50_ms": round(1000 * q(lat, .5), 2), "lat_p95_ms": round(1000 * q(lat, .95), 2),
                 "lat_p99_ms": round(1000 * q(lat, .99), 2),
                 "lat_last_quarter_p50_ms": round(1000 * q(late, .5), 2) if late else None,
                 "service_p50_ms": round(1000 * q([r[2] for r in recs], .5), 3),
                 "history_p50_ms": round(1000 * q([r[3] for r in recs], .5), 3),
                 "history_p99_ms": round(1000 * q([r[3] for r in recs], .99), 3),
                 "max_queue": max(d for _, d in depth), "abstained": sum(r[4] == "abstain" for r in recs)}
            print(json.dumps(s), flush=True)
            with open(a.out, "a") as fh:
                fh.write(json.dumps({"summary": s, "queue_depth": depth}) + "\n")
    finally:
        await redis.client.flushdb()
        await redis.close()


if __name__ == "__main__":
    asyncio.run(main())
