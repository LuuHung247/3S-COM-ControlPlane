#!/usr/bin/env python3
"""
eval_killchain.py — Sequential Kill-Chain Attack Case Study

Submits 3 alerts trong 1 cửa sổ vài phút từ CÙNG src_ip, mô phỏng multi-stage:
  Stage 1: ICMP recon
  Stage 2: WEB→DB lateral movement
  Stage 3: DB outbound exfiltration

Mục đích: quan sát agent reasoning từng stage để verify cumulative context
(alert history, asset reputation, kill-chain correlation) có thay đổi
behavior across stages hay không.

Khác với eval_iid.py (i.i.d. resets mỗi run), script này:
  - KHÔNG reset state giữa các alerts trong 1 chain (state-dependence là point)
  - Report narrative timeline + reasoning trace per alert
  - Xuất Markdown case study, không phải statistical aggregates

Usage:
    python3 eval_killchain.py        # constants ở đầu file (RUNS chains)

Requires: rich
"""
from __future__ import annotations

import datetime
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich.rule import Rule
except ImportError:
    sys.exit("Missing: pip3 install rich")

console = Console()


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

    # Flush Redis DB 0 (agent state) only. DB 1 EventsStore is persistent
    # 7-day FE Monitor buffer — flushing it would erase live UI display.
    subprocess.run(
        ["docker", "compose", "-f", "/home/dis/deploy/zerotrust/docker-compose.yml",
         "exec", "-T", "redis", "redis-cli", "-n", "0", "FLUSHDB"],
        capture_output=True, timeout=10,
    )
    print("    ✓ Redis DB 0 flushed — DB 1 EventsStore intact")

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
    sig = alert["alert"]["signature"]
    console.print(f"  [bold cyan]stage {stage_idx + 1}[/]  [dim]T+{gap_seconds:>3}s[/]  "
                  f"SID [bold]{sid}[/]  [dim]{sig}[/]")
    sent_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    resp = http_post(f"{INTEL}/alerts", {"data": alert})
    if not resp:
        console.print("    [red]✗ request failed entirely[/]")
        return StageResult(stage=stage_idx + 1, sid=sid, sent_at=sent_at,
                           outcome="error", rejection_reason="HTTP failure")
    if resp.get("error"):
        console.print(f"    [red]✗ {resp['error']}[/]")
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
    outcome_color = {"enforced": "green", "dry_run": "yellow", "rejected": "red", "error": "red"}.get(res.outcome, "dim")
    cf = f"{res.confidence:.2f}" if res.confidence is not None else "—"
    console.print(f"    [{outcome_color}]→ outcome={res.outcome}[/]  action={res.action or '—'}  "
                  f"confidence={cf}  latency={res.latency_ms}ms")

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
RUNS = 10                                 # number of independent chain trials (each = 3 alerts)
ATTACKER_IP = "10.1.100.10"               # web-01 (presentation tier)
TARGET_IP = "10.1.200.10"                 # db-01 (used for stages 1-2)
GAP_SECONDS = 30                          # interval between alerts WITHIN a chain
PAUSE_BETWEEN_CHAINS_SECONDS = 5          # cool-down between chains (cleanup gives clean baseline)


def _default_output() -> str:
    # Filename: <test_title>_<YYYYMMDD>_<HHMMSS>.md  (date + time of run)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    os.makedirs(results_dir, exist_ok=True)
    return os.path.join(results_dir, f"eval_killchain_{ts}.md")


# ── Rich UI helpers ──────────────────────────────────────────────────────────

def _render_header() -> None:
    title = Text()
    title.append("ZT-EVAL · KILLCHAIN", style="bold magenta")
    title.append("  ", style="")
    title.append("Sequential Multi-Stage Case Study", style="dim")
    console.print()
    console.print(Panel(
        Align.center(title),
        border_style="magenta",
        padding=(0, 2),
    ))

    cfg = Table.grid(padding=(0, 2))
    cfg.add_column(style="dim")
    cfg.add_column(style="bold")
    cfg.add_row("scenario",      "ICMP recon → WEB→DB lateral → DB outbound exfil")
    cfg.add_row("attacker IP",   ATTACKER_IP)
    cfg.add_row("target IP",     TARGET_IP)
    cfg.add_row("chains",        str(RUNS))
    cfg.add_row("stages/chain",  "3")
    cfg.add_row("intra-stage gap", f"{GAP_SECONDS}s")
    cfg.add_row("inter-chain pause", f"{PAUSE_BETWEEN_CHAINS_SECONDS}s")
    cfg.add_row("est. duration", f"~{(3 * GAP_SECONDS + PAUSE_BETWEEN_CHAINS_SECONDS) * RUNS // 60} min")
    console.print(Panel(cfg, title="[bold]config[/]", border_style="dim", padding=(1, 2)))
    console.print()


def _render_summary(all_runs: list[list[StageResult]]) -> None:
    """Per-stage aggregate table: confidence + latency mean ± stdev."""
    if not all_runs:
        return

    tbl = Table(
        title=f"summary — {len(all_runs)} chains × 3 stages",
        title_style="bold",
        header_style="bold magenta",
        border_style="dim",
    )
    tbl.add_column("stage",       width=6)
    tbl.add_column("SID",         justify="right", width=8)
    tbl.add_column("conf  μ ± σ", justify="right", width=15)
    tbl.add_column("latency (ms) μ ± σ", justify="right", width=22)
    tbl.add_column("n",           justify="right", style="dim")

    for stage_idx in range(3):
        confs = [r[stage_idx].confidence for r in all_runs
                 if len(r) > stage_idx and r[stage_idx].confidence is not None]
        lats = [r[stage_idx].latency_ms for r in all_runs
                if len(r) > stage_idx and r[stage_idx].latency_ms is not None]
        if not confs and not lats:
            tbl.add_row(str(stage_idx + 1), "?", "—", "—", "0")
            continue
        cmean = statistics.mean(confs) if confs else float("nan")
        cstd = statistics.stdev(confs) if len(confs) > 1 else 0.0
        lmean = statistics.mean(lats) if lats else float("nan")
        lstd = statistics.stdev(lats) if len(lats) > 1 else 0.0
        sid = all_runs[0][stage_idx].sid if all_runs and len(all_runs[0]) > stage_idx else "?"
        tbl.add_row(
            str(stage_idx + 1),
            str(sid),
            f"{cmean:.3f} ± {cstd:.3f}",
            f"{lmean:.0f} ± {lstd:.0f}",
            str(len(confs)),
        )
    console.print(tbl)
    console.print()


def _run_one_chain(run_idx: int) -> list[StageResult]:
    """Execute one chain (3 alerts) and write per-chain markdown + json."""
    output_path = _default_output()

    console.print(Rule(f"chain {run_idx}/{RUNS}", style="magenta", characters="─"))
    console.print(f"  [dim]output → {output_path}[/]\n")

    initial_cleanup()

    alerts = chain_alerts(ATTACKER_IP, TARGET_IP)
    stages: list[StageResult] = []
    chain_start = time.time()
    for i, alert in enumerate(alerts):
        gap = int(time.time() - chain_start)
        res = submit_stage(i, alert, gap)
        stages.append(res)
        if i < len(alerts) - 1:
            console.print(f"  [dim]wait {GAP_SECONDS}s before next stage…[/]\n")
            time.sleep(GAP_SECONDS)

    md = render_markdown(stages, ATTACKER_IP, TARGET_IP)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md)
    json_path = output_path.replace(".md", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([s.__dict__ for s in stages], f, indent=2, default=str)
    console.print()
    console.print(f"  [bold green]✓[/] Markdown → [cyan]{output_path}[/]")
    console.print(f"  [bold green]✓[/] JSON     → [cyan]{json_path}[/]\n")
    return stages


def main() -> int:
    _render_header()

    console.print(Rule("preflight", style="dim"))
    h = http_get(f"{INTEL}/health")
    if not h or h.get("status") != "ok":
        console.print(f"  [bold red]✗ intel-layer not healthy:[/] {h}")
        return 2
    console.print(f"  [green]✓[/] intel-layer ok  [dim](dry_run={h.get('dry_run')})[/]\n")

    all_runs: list[list[StageResult]] = []
    for run_idx in range(1, RUNS + 1):
        stages = _run_one_chain(run_idx)
        all_runs.append(stages)
        if run_idx < RUNS:
            console.print(f"  [dim]pause {PAUSE_BETWEEN_CHAINS_SECONDS}s before next chain…[/]\n")
            time.sleep(PAUSE_BETWEEN_CHAINS_SECONDS)

    console.print(Rule("cleanup", style="dim"))
    try:
        subprocess.run(
            ["docker", "compose", "-f", "/home/dis/deploy/zerotrust/docker-compose.yml",
             "exec", "-T", "postgres", "psql", "-U", "ztuser", "-d", "zerotrust",
             "-c", "TRUNCATE TABLE decisions;"],
            capture_output=True, timeout=10,
        )
        console.print("  [green]✓[/] decisions truncated [dim](decisions_history preserved)[/]\n")
    except Exception as e:
        console.print(f"  [red]✗ truncate failed:[/] {e}\n")

    console.print(Rule("results", style="bold magenta"))
    console.print()
    _render_summary(all_runs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
