#!/usr/bin/env python3
"""Replay fixture alerts through the HTTP API, measure latency."""
import asyncio
import json
import sys
import time
import argparse
import httpx


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alerts", default="tests/fixtures/alerts.json")
    parser.add_argument("--url", default="http://localhost:8767")
    args = parser.parse_args()

    with open(args.alerts) as f:
        alerts = json.load(f)

    print(f"Replaying {len(alerts)} alerts → {args.url}")
    latencies = []

    async with httpx.AsyncClient(timeout=30) as client:
        for alert in alerts:
            t0 = time.monotonic()
            resp = await client.post(f"{args.url}/alerts", json={"data": alert})
            elapsed = (time.monotonic() - t0) * 1000
            latencies.append(elapsed)
            data = resp.json()
            print(f"  SID {alert['alert'].get('signature_id')} → outcome={data.get('outcome')} "
                  f"latency={elapsed:.0f}ms")

    if latencies:
        print(f"\nLatency — p50={sorted(latencies)[len(latencies)//2]:.0f}ms "
              f"p95={sorted(latencies)[int(len(latencies)*0.95)]:.0f}ms "
              f"max={max(latencies):.0f}ms")


if __name__ == "__main__":
    asyncio.run(main())
