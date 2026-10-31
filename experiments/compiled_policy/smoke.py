#!/usr/bin/env python3
"""Dry-run smoke test of the compiled fast path and the runtime fallback."""
import json, sys, time, urllib.request
from datetime import datetime, timezone

INTEL = "http://localhost:8767"


def post(p, d, timeout=150):
    r = urllib.request.Request(INTEL + p, data=json.dumps(d).encode(),
                               headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(r, timeout=timeout).read())


CASES = [("WEB->DB 9000001", 9000001, 1, "10.1.100.10", "10.1.200.10", 5432),
         ("destructive SQL APP-CORE->DB (ALLOW)", 9000072, 1, "10.2.100.10", "10.1.200.10", 5432),
         ("SYN contribution 9000051 (doc log_only)", 9000051, 2, "10.1.100.10", "10.3.100.10", 8080),
         ("C2 beacon 9000060 cold (after correlate)", 9000060, 2, "10.4.100.10", "8.8.8.8", 443),
         ("unknown SID (runtime LLM)", 9000903, 2, "10.2.100.10", "10.1.100.10", 22)]

if __name__ == "__main__":
    print(post("/admin/compiled", {"enabled": True, "path": "compiled/policy.json"}))
    for name, sid, sev, s, d, port in CASES:
        post("/admin/reset", {})
        a = {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "alert",
             "src_ip": s, "dest_ip": d, "src_port": 46000, "dest_port": port, "proto": "TCP",
             "alert": {"signature_id": sid, "severity": sev, "signature": name, "category": "test"}}
        t = time.time()
        r = post("/alerts", {"data": a})
        print(f"{name:42s} path={r.get('decision_path'):8s} outcome={r['outcome']:9s} "
              f"action={r.get('action')} rule={r.get('dst_ip')}:{r.get('dst_port')} ttl={r.get('ttl_seconds')} "
              f"agent_ms={r['latency_ms']:.1f} http_s={time.time() - t:.2f} "
              f"{(r.get('rejection_reason') or '')[:60]} {r.get('persist_error') or ''}")
