#!/usr/bin/env python3
"""
eval_chain_attack.py — Sequential kill-chain attack case study (Eval B)

Submits 3 alerts in a 5-minute window from the SAME src_ip, simulating a
multi-stage attack: ICMP recon → WEB→DB lateral → DB outbound exfil. Captures
the agent's reasoning at each step so we can verify whether the cumulative
context (alert history, asset reputation, multi-strategy past-incident
retrieval, kill-chain correlation) actually changes behavior across stages.

Unlike eval.py (Eval A — i.i.d. independent runs with full state reset
between every iteration), this script:
  - Does NOT reset state between alerts (state-dependence is the point)
  - Reports a narrative timeline + reasoning trace per alert
  - Outputs a single Markdown case study, not statistical aggregates

Usage:
    python3 eval_chain_attack.py
    python3 eval_chain_attack.py --src-ip 10.1.100.10 --output case_study.md
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


INTEL = os.getenv("INTEL_URL", "http://localhost:8767")
IDS_AGENT = os.getenv("IDS_AGENT_URL", "http://localhost:8766")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────
def http_post(url: str, body: dict, timeout: int = 30) -> dict | None:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {"error": f"HTTP {e.code}", "body": str(e.reason)}
    except Exception as e:
        return {"error": str(e)}


def http_get(url: str, timeout: int = 8) -> Any:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def http_delete(url: str, timeout: int = 8) -> bool:
    try:
        req = urllib.request.Request(url, method="DELETE")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status < 400
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup helpers (we do this ONCE before the chain, not between alerts)
# ─────────────────────────────────────────────────────────────────────────────
def initial_cleanup() -> None:
    print("\n  [setup] Clearing prior state for clean baseline...")

    # Wipe agent rules
    rules = http_get(f"{IDS_AGENT}/rules?source=agent") or []
    if isinstance(rules, dict):
        rules = [r for r in rules.get("rules", []) if r.get("source") == "agent"]
    deleted = 0
    for r in rules:
        rid = r.get("rule-id") or r.get("rule_id")
        if rid and http_delete(f"{IDS_AGENT}/rules/{rid}"):
            deleted += 1
    print(f"    ✓ deleted {deleted} prior agent rules")

    # Flush Redis DB 0 (state) + DB 1 (events) for clean baseline
    for db in ("0", "1"):
        subprocess.run(
            ["docker", "compose", "-f", "/home/dis/deploy/zerotrust/docker-compose.yml",
             "exec", "-T", "redis", "redis-cli", "-n", db, "FLUSHDB"],
            capture_output=True, timeout=10,
        )
    print("    ✓ Redis DB 0 + DB 1 flushed")

    # Truncate workspace `decisions` only — decisions_history is preserved
    # so FE Policy History keeps every prior decision visible.
    subprocess.run(
        ["docker", "compose", "-f", "/home/dis/deploy/zerotrust/docker-compose.yml",
         "exec", "-T", "postgres", "psql", "-U", "ztuser", "-d", "zerotrust",
         "-c", "TRUNCATE TABLE decisions;"],
        capture_output=True, timeout=10,
    )
    print("    ✓ workspace decisions truncated (decisions_history preserved)")

    # Reset rate limiter / circuit breaker
    http_post(f"{INTEL}/admin/reset", {})
    print("    ✓ Intel-layer rate limiter + circuit breaker reset")


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Suricata alerts (EVE JSON shape) — matches dataplane SID catalog
# ─────────────────────────────────────────────────────────────────────────────
def build_alert(
    sid: int,
    severity: int,
    signature: str,
    src_ip: str,
    dest_ip: str,
    dest_port: int,
    proto: str = "tcp",
    category: str = "Lateral Movement",
) -> dict:
    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": "alert",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": 51234,
        "dest_port": dest_port,
        "proto": proto.upper(),
        "alert": {
            "signature_id": sid,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
        "flow_id": int(time.time() * 1_000_000),
    }


def chain_alerts(src_ip: str, dst_ip: str) -> list[dict]:
    """Recon → Lateral → Exfil — same src_ip, escalating signatures."""
    return [
        # Stage 1: ICMP ping sweep (recon, P3)
        build_alert(
            sid=9000010, severity=3,
            signature="ICMP ping sweep — reconnaissance",
            src_ip=src_ip, dest_ip=dst_ip, dest_port=0, proto="icmp",
            category="Attempted Information Leak",
        ),
        # Stage 2: WEB→DB lateral movement (P1)
        build_alert(
            sid=9000001, severity=1,
            signature="WEB direct to DB — microsegmentation bypass",
            src_ip=src_ip, dest_ip=dst_ip, dest_port=5432, proto="tcp",
            category="Lateral Movement",
        ),
        # Stage 3: DB outbound exfiltration (P1) — agent of attacker pivoted
        build_alert(
            sid=9000002, severity=1,
            signature="DB initiating outbound — possible exfil",
            src_ip=src_ip, dest_ip="8.8.8.8", dest_port=443, proto="tcp",
            category="Exfiltration",
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Submit + capture
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class StageResult:
    stage: int
    sid: int
    sent_at: str
    decision_id: str = ""
    outcome: str = ""
    action: str = ""
    confidence: float | None = None
    rejection_reason: str = ""
    ttl_seconds: int | None = None
    latency_ms: float | None = None
    primary_hypothesis: str = ""
    reasoning_first: str = ""
    raw: dict = field(default_factory=dict)


def submit_stage(stage_idx: int, alert: dict, gap_seconds: int) -> StageResult:
    sid = alert["alert"]["signature_id"]
    print(f"\n  [stage {stage_idx + 1}] T+{gap_seconds:>3}s — sending SID {sid} "
          f"({alert['alert']['signature']})...")
    sent_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    resp = http_post(f"{INTEL}/alerts", {"data": alert})
    if not resp:
        print("    ✗ request failed entirely")
        return StageResult(stage=stage_idx + 1, sid=sid, sent_at=sent_at,
                           outcome="error", rejection_reason="HTTP failure")
    if resp.get("error"):
        print(f"    ✗ {resp['error']}")
        return StageResult(stage=stage_idx + 1, sid=sid, sent_at=sent_at,
                           outcome="error", rejection_reason=str(resp))

    res = StageResult(
        stage=stage_idx + 1, sid=sid, sent_at=sent_at,
        decision_id=resp.get("id", ""),
        outcome=resp.get("outcome", ""),
        action=resp.get("action", "") or "",
        confidence=resp.get("confidence"),
        rejection_reason=resp.get("rejection_reason", "") or "",
        latency_ms=resp.get("latency_ms"),
        raw=resp,
    )
    print(f"    → outcome={res.outcome} action={res.action} "
          f"confidence={res.confidence} latency={res.latency_ms}ms")

    # Wait for V3 Stage 2 reasoning trace to populate, then enrich
    if res.decision_id and res.decision_id != "filtered":
        for _ in range(12):
            time.sleep(0.5)
            d = http_get(f"{INTEL}/decisions/{res.decision_id}")
            if d and not d.get("reasoning_loading", False):
                res.primary_hypothesis = d.get("primary_hypothesis", "") or ""
                rs = d.get("reasoning", []) or []
                if rs:
                    res.reasoning_first = rs[0][:240]
                res.ttl_seconds = d.get("ttl_seconds")
                res.raw["full_decision"] = d
                break

    return res


# ─────────────────────────────────────────────────────────────────────────────
# Markdown report
# ─────────────────────────────────────────────────────────────────────────────
def render_markdown(stages: list[StageResult], src_ip: str, dst_ip: str) -> str:
    lines = [
        "# Chain Attack Case Study",
        "",
        f"- **Attacker IP**: `{src_ip}`",
        f"- **Target IP**: `{dst_ip}`",
        f"- **Run at**: {datetime.datetime.now().isoformat(timespec='seconds')}",
        "- **Premise**: 3 sequential alerts in a 5-minute window. State-dependent — no reset between stages.",
        "- **Question**: does cumulative context (alert history, reputation, past-incident retrieval) change agent behavior across stages?",
        "",
        "## Timeline",
        "",
        "| Stage | T+ | SID | Outcome | Action | Confidence | Latency | TTL | Decision ID |",
        "|------:|---:|----:|---------|--------|-----------:|--------:|----:|-------------|",
    ]
    base_t = datetime.datetime.fromisoformat(stages[0].sent_at) if stages else None
    for s in stages:
        t_offset = ""
        if base_t:
            try:
                cur = datetime.datetime.fromisoformat(s.sent_at)
                t_offset = f"{int((cur - base_t).total_seconds())}s"
            except Exception:
                pass
        conf = f"{s.confidence:.2f}" if s.confidence is not None else "—"
        lat = f"{s.latency_ms:.0f}ms" if s.latency_ms is not None else "—"
        ttl = f"{s.ttl_seconds}" if s.ttl_seconds is not None else "—"
        did = s.decision_id[:12] if s.decision_id else "—"
        lines.append(
            f"| {s.stage} | {t_offset} | {s.sid} | {s.outcome} | {s.action or '—'} | "
            f"{conf} | {lat} | {ttl} | `{did}` |"
        )

    lines += ["", "## Reasoning per stage", ""]
    for s in stages:
        lines.append(f"### Stage {s.stage} — SID {s.sid}")
        lines.append(f"- Hypothesis: {s.primary_hypothesis or '(none captured)'}")
        if s.reasoning_first:
            lines.append(f"- First reasoning step: {s.reasoning_first}")
        if s.rejection_reason:
            lines.append(f"- Rejection reason: {s.rejection_reason}")
        lines.append("")

    lines += [
        "## Notes for thesis",
        "",
        "Compare confidence and latency across stages 1→3. If the agent's cumulative",
        "memory works, expect:",
        "- Stage 2 confidence ≥ Stage 1 (history adds signal).",
        "- Stage 3 confidence highest (chain progression confirmed by recurrence + reputation).",
        "- Stage 3 may also fire faster if upstream blocks already affect attacker reachability.",
        "- A stable or rising confidence trend is positive evidence for institutional memory.",
        "- If confidence is flat or declining, document it — that's also a finding.",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
# ── Configuration (edit here, no CLI args) ──────────────────────────────────
ATTACKER_IP = "10.1.100.10"               # web-01 (presentation tier)
TARGET_IP = "10.1.200.10"                 # db-01 (used for stages 1-2)
GAP_SECONDS = 30                          # interval between alerts in the chain
RUN_INITIAL_CLEANUP = True                # False to resume on existing state


def _default_output() -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    os.makedirs(results_dir, exist_ok=True)
    return os.path.join(results_dir, f"chain_attack_{ts}.md")


def main() -> int:
    output_path = _default_output()

    print("=" * 70)
    print(" Eval B — Chain Attack Case Study (sequential, state-dependent)")
    print(" Zero Trust Intelligence Layer")
    print("=" * 70)
    print(f"  ATTACKER_IP          = {ATTACKER_IP}")
    print(f"  TARGET_IP            = {TARGET_IP}")
    print(f"  GAP_SECONDS          = {GAP_SECONDS}")
    print(f"  RUN_INITIAL_CLEANUP  = {RUN_INITIAL_CLEANUP}")
    print(f"  OUTPUT               = {output_path}")

    h = http_get(f"{INTEL}/health")
    if not h or h.get("status") != "ok":
        print(f"\n[FATAL] intel-layer not healthy: {h}")
        return 2
    print(f"  intel-layer          = ok (dry_run={h.get('dry_run')})")

    if RUN_INITIAL_CLEANUP:
        initial_cleanup()
    else:
        print("\n  [setup] RUN_INITIAL_CLEANUP=False — using current state")

    alerts = chain_alerts(ATTACKER_IP, TARGET_IP)
    stages: list[StageResult] = []

    print(f"\n  [chain] sending {len(alerts)} alerts with {GAP_SECONDS}s gaps...")
    chain_start = time.time()
    for i, alert in enumerate(alerts):
        gap = int(time.time() - chain_start)
        res = submit_stage(i, alert, gap)
        stages.append(res)
        if i < len(alerts) - 1:
            print(f"\n  [wait] {GAP_SECONDS}s before next stage...")
            time.sleep(GAP_SECONDS)

    md = render_markdown(stages, ATTACKER_IP, TARGET_IP)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md)

    json_path = output_path.replace(".md", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([s.__dict__ for s in stages], f, indent=2, default=str)

    print("\n" + "=" * 70)
    print(f" Report:    {output_path}")
    print(f" Raw JSON:  {json_path}")
    print("=" * 70)

    # Final cleanup: experiment is over. Wipe workspace `decisions` so the next
    # experiment starts fresh. `decisions_history` is preserved for FE display.
    print("\n  [final cleanup] truncating workspace decisions table...")
    try:
        subprocess.run(
            ["docker", "compose", "-f", "/home/dis/deploy/zerotrust/docker-compose.yml",
             "exec", "-T", "postgres", "psql", "-U", "ztuser", "-d", "zerotrust",
             "-c", "TRUNCATE TABLE decisions;"],
            capture_output=True, timeout=10,
        )
        print("    ✓ decisions truncated (decisions_history preserved)")
    except Exception as e:
        print(f"    ✗ truncate failed: {e}")

    print()
    for s in stages:
        cf = f"{s.confidence:.2f}" if s.confidence is not None else "—"
        print(f"  stage{s.stage} SID{s.sid}: {s.outcome:8s} conf={cf} action={s.action or '—'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
