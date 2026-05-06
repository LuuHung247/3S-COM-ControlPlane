#!/usr/bin/env python3
"""
eval_memory.py — Zero Trust Intelligence Layer · Memory-Stateful Eval

Đối ngược với eval_iid.py:
  - eval_iid TRUNCATE `decisions` mỗi run → memory empty mỗi lần → i.i.d. baseline
  - eval_memory KEEP `decisions` qua các runs → run N thấy lịch sử run 1..N-1

Mục đích: kiểm tra agent memory thực sự có hoạt động không. Cùng attacker IP,
cùng scenario lặp N lần. Kỳ vọng:
  - Run 1: agent thấy attack lần đầu → confidence baseline, MTTD đầy đủ
  - Run N (N lớn): agent past-incident retrieval kéo về N-1 decisions trước
                   → confidence cao hơn / latency thấp hơn / reasoning ngắn hơn

Đo lường (giống eval_iid):
  - MTTD (alert ghi → decision created)
  - M1 Alert→Decision (s)
  - M2 Decision→LEAF (ms)
  - Confidence — kỳ vọng tăng dần theo run number
  - Outcome correctness

Xuất Excel + JSON. Run number được preserve để có thể plot confidence vs run.

Usage:
    python3 eval_memory.py        # constants ở đầu file (RUNS=10)

Requires: openpyxl, rich
"""
import datetime
import json
import math
import os
import socket
import statistics
import subprocess
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
except ImportError:
    sys.exit("Missing: pip3 install openpyxl")

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.rule import Rule
except ImportError:
    sys.exit("Missing: pip3 install rich")

console = Console()

# ── Config ──────────────────────────────────────────────────────────────────
IDS_API   = os.getenv("IDS_API_URL",   "http://10.10.6.238:8765")
IDS_AGENT = os.getenv("IDS_AGENT_URL", "http://localhost:8766")
INTEL     = os.getenv("INTEL_URL",     "http://localhost:8767")
SF_API    = os.getenv("SF_API_URL",    "http://10.10.6.238:9090")
MGT_CONSOLE_HOST = os.getenv("MGT_CONSOLE_HOST", "10.10.6.238")
MGT_CONSOLE_PORT = int(os.getenv("MGT_CONSOLE_PORT", "5016"))
ATTACKER_IP  = "10.1.100.10"
TARGET_SID   = 9000001
POLL_INTERVAL = 10   # seconds — keep Suricata IDS API load low (re-reads 100MB eve.json per request)

# ── HTTP helpers ─────────────────────────────────────────────────────────────

def http_get(url: str, timeout: int = 8):
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

# ── Console helper (MGT host via GNS3 telnet proxy) ─────────────────────────

def _console_drain(s: socket.socket, wait: float = 1.5) -> str:
    time.sleep(wait)
    out = b""
    s.settimeout(0.4)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except Exception:
        pass
    return out.decode(errors="ignore")

def console_run(cmd: str, wait: float = 4.0) -> str:
    """Run a shell command on MGT host via console proxy port 5016."""
    try:
        s = socket.socket()
        s.connect((MGT_CONSOLE_HOST, MGT_CONSOLE_PORT))
        s.settimeout(2)
        _console_drain(s, 0.4)
        s.sendall(b"\n")
        _console_drain(s, 0.4)
        s.sendall(b"root\n")
        _console_drain(s, 0.6)
        s.sendall((cmd + "\n").encode())
        out = _console_drain(s, wait)
        s.close()
        return out
    except Exception as e:
        return f"CONSOLE_ERROR: {e}"

# ── Suricata alert helpers ────────────────────────────────────────────────────

def get_alerts_since(since_ts: float, last: int = 200) -> list:
    """Return alerts from IDS API fired after since_ts (unix)."""
    since_str = datetime.datetime.utcfromtimestamp(since_ts).strftime("%Y-%m-%dT%H:%M:%S")
    data = http_get(f"{IDS_API}/alerts?last={last}&since={urllib.request.quote(since_str)}")
    # API may return {"count":N, "alerts":[...]} or plain list
    if isinstance(data, dict):
        data = data.get("alerts", [])
    if not isinstance(data, list):
        data = http_get(f"{IDS_API}/alerts?last={last}")
        if isinstance(data, dict):
            data = data.get("alerts", [])
    if not isinstance(data, list):
        return []
    return [a for a in data if _alert_ts(a) >= since_ts]

def _alert_ts(alert: dict) -> float:
    ts_str = alert.get("timestamp") or alert.get("flow_start_time") or ""
    if not ts_str:
        return 0.0
    # Normalize timezone: "Z" → "+00:00", "+0000" → "+00:00" (Python 3.8 compat)
    ts_str = ts_str.replace("Z", "+00:00")
    import re as _re
    ts_str = _re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', ts_str)
    try:
        return datetime.datetime.fromisoformat(ts_str).timestamp()
    except Exception:
        return 0.0

def first_p1_alert(alerts: list) -> Optional[dict]:
    for a in alerts:
        if a.get("alert", {}).get("signature_id") == TARGET_SID:
            return a
        if a.get("signature_id") == TARGET_SID:
            return a
    return None

# ── Agent decision helpers ────────────────────────────────────────────────────

def get_decisions_since(since_ts: float, limit: int = 50) -> list:
    data = http_get(f"{INTEL}/decisions?limit={limit}")
    if not isinstance(data, list):
        data = (data or {}).get("decisions", [])
    out = []
    for d in (data or []):
        try:
            created = datetime.datetime.fromisoformat(
                d.get("created_at", "").replace("Z", "+00:00")
            ).timestamp()
        except Exception:
            created = 0.0
        if created >= since_ts and d.get("alert_sid") == TARGET_SID:
            out.append(d)
    return out

def decision_confidence(d: dict) -> Optional[float]:
    sc = d.get("safety_checks") or {}
    return (sc.get("confidence") or {}).get("score")

# ── SF rules helpers ──────────────────────────────────────────────────────────

def get_agent_rules_from_sf() -> list:
    data = http_get(f"{SF_API}/api/rules")
    if not data:
        return []
    found = []
    for leaf_data in (data.get("leaves") or {}).values():
        for notif in (leaf_data.get("rules") or {}).get("notification", []):
            for upd in notif.get("update", []):
                val = upd.get("val", {})
                if val.get("source") == "agent":
                    val["_path"] = upd.get("path", "")
                    found.append(val)
    return found

def rule_blocks_attacker(rules: list) -> bool:
    for r in rules:
        # SF returns src-prefix (gNMI YANG field name)
        src = r.get("src-prefix") or r.get("src_ip") or r.get("source-ip") or ""
        if ATTACKER_IP in src or src.startswith(ATTACKER_IP.split("/")[0]):
            return True
    return False

def get_agent_rule_ids_from_agent() -> list:
    """Parse gNMI notification format from IDS agent /rules endpoint."""
    data = http_get(f"{IDS_AGENT}/rules")
    if not data:
        return []
    ids = []
    # Same gNMI format as SF API: {leaves: {leaf-N: {rules: {notification: [{update: [{val:{...}}]}]}}}}
    for leaf_data in (data.get("leaves") or {}).values():
        for notif in (leaf_data.get("rules") or {}).get("notification", []):
            for upd in notif.get("update", []):
                val = upd.get("val", {})
                if val.get("source") == "agent":
                    rid = val.get("rule-id") or val.get("rule_id")
                    if rid and rid not in ids:
                        ids.append(rid)
    return ids

# ── Reset between runs ────────────────────────────────────────────────────────

def cleanup_agent_rules(prefix: str = "  [cleanup]") -> int:
    """Delete every agent-pushed rule from the SF (via ids-agent proxy).
    Returns number of rules deleted. Idempotent."""
    rule_ids = get_agent_rule_ids_from_agent()
    if not rule_ids:
        console.print(f"{prefix}[dim] no agent rules to remove[/]")
        return 0
    deleted = 0
    for rid in rule_ids:
        ok = http_delete(f"{IDS_AGENT}/rules/{rid}")
        if ok:
            console.print(f"{prefix} [green]✓[/] DELETE rule [cyan]{rid}[/]")
            deleted += 1
        else:
            console.print(f"{prefix} [red]✗[/] DELETE rule [cyan]{rid}[/]")
    return deleted


def reset(run_num: int) -> float:
    """Reset between runs but PRESERVE `decisions` (agent memory).

    Difference vs eval_iid.reset():
      - eval_iid TRUNCATEs `decisions` table → each run sees empty memory (i.i.d.)
      - eval_memory KEEPS `decisions` → run N sees memory from runs 1..N-1

    This is the whole point of this eval: measure if accumulated memory
    (past-incident retrieval, asset reputation, kill-chain correlation) makes
    the agent faster / more confident on subsequent attacks from the same src_ip.

    What we still reset:
      - Disarm attack scenario (so next run can re-trigger cleanly)
      - Delete prior agent-pushed SF rules (else LEAF blocks SYN before Suricata
        sees it → no alert → can't measure)
      - Flush Redis DB 0 (rate limiter / circuit breaker / cache — should not
        leak across runs; the durable memory lives in Postgres)
      - Reset intel-layer rate limiter

    What stays intact:
      - Postgres `decisions` table  ← THE memory under test
      - Postgres `decisions_history` ← FE audit (also untouched in eval_iid)
      - Redis DB 1 EventsStore       ← FE Monitor buffer
    """
    console.print("  [yellow]\[reset][/] Disarming scenario...")
    console_run("/root/scenario/restore-web.sh", wait=5.0)

    console.print("  [yellow]\[reset][/] Deleting agent-pushed rules [dim](else LEAF blocks SYN before Suricata)[/]...")
    cleanup_agent_rules(prefix="    ")

    console.print("  [yellow]\[reset][/] Flushing Redis DB 0 [dim](rate limiter / cache; DB 1 + Postgres `decisions` preserved)[/]...")
    try:
        subprocess.run(
            ["docker", "compose", "-f", "/home/dis/deploy/zerotrust/docker-compose.yml",
             "exec", "-T", "redis", "redis-cli", "-n", "0", "FLUSHDB"],
            capture_output=True, timeout=10
        )
        console.print("    [green]✓[/] Redis DB 0 flushed")
    except Exception as e:
        console.print(f"    [red]✗[/] Redis flush failed: {e}")

    # NOTE: NO `TRUNCATE TABLE decisions` here — that's the whole point.
    # Agent reads Postgres `decisions` for asset reputation, multi-strategy
    # past-incident search, kill-chain correlation. Keeping those rows means
    # run N sees memory of runs 1..N-1.
    console.print("  [yellow]\[reset][/] Postgres `decisions` [bold magenta]PRESERVED[/] [dim](memory under test)[/]")

    console.print("  [yellow]\[reset][/] Resetting intel-layer rate limiter...")
    try:
        req = urllib.request.Request(f"{INTEL}/admin/reset", data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            console.print("    [green]✓[/] Rate limiter reset")
    except Exception as e:
        console.print(f"    [red]✗[/] Admin reset failed: {e}")

    anchor_ts = time.time()
    clear = http_get(f"{IDS_API}/alerts/clear")
    if clear and clear.get("cleared_at"):
        try:
            anchor_ts = datetime.datetime.fromisoformat(
                clear["cleared_at"].replace("Z", "+00:00")
            ).timestamp()
            console.print(f"    [green]✓[/] Alert anchor: [cyan]{clear['cleared_at']}[/]")
        except Exception:
            console.print(f"    [green]✓[/] Alert anchor set (raw): {clear}")
    else:
        console.print("    [yellow](no /alerts/clear — using local timestamp anchor)[/]")

    time.sleep(5)
    return anchor_ts

# ── Run single scenario ───────────────────────────────────────────────────────

@dataclass
class RunResult:
    run_num: int
    started_at: str = ""
    outcome: str = "none"
    mttd_s: Optional[float] = None
    enforce_latency_ms: Optional[float] = None
    total_latency_s: Optional[float] = None
    confidence: Optional[float] = None
    alert_count_p1: int = 0
    rule_pushed: bool = False
    rule_id: str = ""
    rejection_reason: str = ""
    dry_run: bool = True
    checks_pass: int = 0
    checks_total: int = 5
    passed: bool = False
    notes: str = ""
    # ── New metrics ──────────────────────────────────────────────────────────
    t_alert_to_decision_s: Optional[float] = None    # Metric 1: T_decision.created_at − T_alert.timestamp
    t_decision_to_enforce_ms: Optional[float] = None # Metric 2: SF rule visible − T_decision.created_at
    enforcement_correct: Optional[bool] = None        # Metric 3: decision src_ip matches attacker

def run_scenario(run_num: int, duration: int, anchor_ts: float = 0.0) -> RunResult:
    result = RunResult(run_num=run_num)
    result.started_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # 1. Pre-attack baseline
    pre_rules = get_agent_rules_from_sf()

    # 2. Trigger attack
    console.print("  [bold yellow]\[T+0][/] Triggering compromise-web...")
    t_attack = time.time()
    console_out = console_run("/root/scenario/compromise-web.sh", wait=5.0)
    if "armed" in console_out.lower() or "arming" in console_out.lower():
        console.print("    [green]✓[/] Attack armed")
    else:
        console.print(f"    [yellow]?[/] Console output: [dim]{console_out[-100:].strip()}[/]")
    # Use anchor from /alerts/clear if available, else fall back to t_attack
    since_ts = anchor_ts if anchor_ts > 0 else t_attack

    # 3. Poll until decision or timeout
    t_first_alert = None
    decision = None
    deadline = t_attack + duration

    console.print(f"  [yellow]\[poll][/] Waiting up to [bold]{duration}s[/] for Agent decision [dim](poll every {POLL_INTERVAL}s)[/]...")
    while time.time() < deadline:
        elapsed = time.time() - t_attack

        # Decision-first polling — DO NOT call Suricata /alerts directly.
        # Reason: Suricata IDS API has a memory leak — every /alerts request
        # parses the full eve.json (~100MB) into RAM. Heavy polling triggers
        # OOM on the dataplane VM. We rely on intel-layer SSE which already
        # streams alerts internally; if a decision exists, an alert fired.
        if decision is None:
            decisions = get_decisions_since(t_attack - 2)
            if decisions:
                decision = decisions[0]
                result.outcome = decision.get("outcome", "unknown")
                result.enforce_latency_ms = round(decision.get("latency_ms") or 0, 1)
                result.confidence = decision_confidence(decision)
                result.rejection_reason = decision.get("rejection_reason") or ""
                result.dry_run = decision.get("dry_run", True)
                outcome_color = {"enforced": "green", "dry_run": "yellow", "rejected": "red"}.get(result.outcome, "dim")
                console.print(f"    [green]✓[/] Decision: outcome=[{outcome_color}]{result.outcome}[/] latency=[bold]{result.enforce_latency_ms}ms[/] confidence=[bold]{result.confidence}[/]")

                # ── Metric 1: Alert detected → Decision created ──────────────
                # MTTD ≈ time from attack arming to decision created_at minus the
                # decision's pipeline latency (= when the alert hit intel-layer).
                t_decision_created = None
                try:
                    t_decision_created = datetime.datetime.fromisoformat(
                        decision["created_at"].replace("Z", "+00:00")
                    ).timestamp()
                    pipeline_latency_s = (decision.get("latency_ms") or 0.0) / 1000.0
                    t_first_alert = t_decision_created - pipeline_latency_s
                    result.mttd_s = round(max(0.0, t_first_alert - t_attack), 1)
                    result.alert_count_p1 = 1   # at least 1 (decision implies alert)
                    console.print(f"    [green]✓[/] SID [cyan]{TARGET_SID}[/] alert at [bold]T+{result.mttd_s}s[/] [dim](inferred from decision)[/]")
                    result.t_alert_to_decision_s = round(t_decision_created - t_first_alert, 2)
                    console.print(f"    [green]✓[/] [bold cyan]\[M1][/] Alert→Decision: [bold]{result.t_alert_to_decision_s}s[/]")
                except Exception:
                    pass

                # ── Metric 3: Enforcement correctness ───────────────────────
                src_ip = decision.get("src_ip") or ""
                result.enforcement_correct = (
                    ATTACKER_IP in src_ip or src_ip.startswith(ATTACKER_IP.rstrip("/"))
                ) if src_ip else None
                m3_icon = "[green]✓[/]" if result.enforcement_correct else "[red]✗[/]"
                m3_color = "green" if result.enforcement_correct else "red"
                console.print(f"    {m3_icon} [bold cyan]\[M3][/] Correct src_ip: [{m3_color}]{result.enforcement_correct}[/] [dim]({src_ip!r})[/]")

                # ── Metric 2: Decision-to-Enforcement (SF poll) ─────────────
                # Enforcement is synchronous in intelligence-layer (rule applied
                # before created_at is written). Poll SF now to confirm rule
                # presence and measure propagation delay from created_at.
                if result.outcome == "enforced" and t_decision_created is not None:
                    for attempt in range(8):
                        sf_rules = get_agent_rules_from_sf()
                        if rule_blocks_attacker(sf_rules):
                            t_rule_seen = time.time()
                            result.t_decision_to_enforce_ms = round(
                                max(0.0, t_rule_seen - t_decision_created) * 1000, 1
                            )
                            console.print(f"    [green]✓[/] [bold cyan]\[M2][/] Rule visible on LEAF at [bold]+{result.t_decision_to_enforce_ms}ms[/] after decision")
                            break
                        time.sleep(1)
                    else:
                        console.print("    [red]✗[/] [bold cyan]\[M2][/] Rule NOT visible on LEAF after 8s")

                break

        sys.stdout.write(f"\r    \033[2melapsed {elapsed:.0f}s ...\033[0m")
        sys.stdout.flush()
        time.sleep(POLL_INTERVAL)

    print()

    # 4. Disarm + post-snapshot
    console_run("/root/scenario/restore-web.sh", wait=4.0)
    time.sleep(3)

    # 5. Check rule in SF
    post_rules = get_agent_rules_from_sf()
    new_agent_rules = [r for r in post_rules if r not in pre_rules]
    result.rule_pushed = rule_blocks_attacker(post_rules)
    if new_agent_rules:
        result.rule_id = new_agent_rules[0].get("_path", "")[:60]

    # 6. Total latency
    if result.mttd_s is not None and result.enforce_latency_ms is not None:
        result.total_latency_s = round(result.mttd_s + result.enforce_latency_ms / 1000, 2)

    # 7. Verify checks
    checks = 0
    total = 5
    if result.alert_count_p1 >= 1:
        checks += 1
    if decision is not None:
        checks += 1
    if result.outcome in ("enforced", "dry_run"):
        checks += 1
    if result.rule_pushed or result.dry_run:
        checks += 1
    if result.mttd_s is not None and (result.enforce_latency_ms or 0) < 30_000:
        checks += 1

    result.checks_pass = checks
    result.checks_total = total
    result.passed = (checks == total) and result.outcome in ("enforced", "dry_run")

    return result

# ── Excel export ──────────────────────────────────────────────────────────────

GREEN  = PatternFill("solid", fgColor="C6EFCE")
RED    = PatternFill("solid", fgColor="FFC7CE")
YELLOW = PatternFill("solid", fgColor="FFEB9C")
HEADER = PatternFill("solid", fgColor="1F4E79")
GRAY   = PatternFill("solid", fgColor="D9D9D9")

COLS = [
    ("Run",                    "run_num"),
    ("Started (UTC)",          "started_at"),
    ("Pass?",                  "passed"),
    ("Outcome",                "outcome"),
    ("MTTD IDS (s)",           "mttd_s"),
    ("M1 Alert→Decision (s)",  "t_alert_to_decision_s"),
    ("M2 Decision→LEAF (ms)",  "t_decision_to_enforce_ms"),
    ("M3 Correct IP",          "enforcement_correct"),
    ("Agent latency (ms)",     "enforce_latency_ms"),
    ("Total E2E (s)",          "total_latency_s"),
    ("Confidence",             "confidence"),
    ("P1 Alerts",              "alert_count_p1"),
    ("Rule Pushed",            "rule_pushed"),
    ("Rule ID",                "rule_id"),
    ("Dry Run",                "dry_run"),
    ("Checks",                 "_checks"),
    ("Rejection",              "rejection_reason"),
    ("Notes",                  "notes"),
]
NUMERIC_COLS = {"mttd_s", "t_alert_to_decision_s", "t_decision_to_enforce_ms",
                "enforce_latency_ms", "total_latency_s", "confidence", "alert_count_p1"}

def export_excel(results: List[RunResult], path: str):
    wb = openpyxl.Workbook()

    # ── Sheet 1: Per-run data ────────────────────────────────────────────────
    ws = wb.active
    ws.title = "Runs"

    header_font = Font(bold=True, color="FFFFFF", size=11)
    for col_idx, (label, _) in enumerate(COLS, 1):
        cell = ws.cell(row=1, column=col_idx, value=label)
        cell.fill = HEADER
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", wrap_text=True)

    for row_idx, r in enumerate(results, 2):
        row_fill = GREEN if r.passed else RED
        for col_idx, (_, attr) in enumerate(COLS, 1):
            if attr == "_checks":
                val = f"{r.checks_pass}/{r.checks_total}"
            else:
                val = getattr(r, attr, "")
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.fill = row_fill
            cell.alignment = Alignment(horizontal="center")

    # Column widths (18 columns)
    widths = [6, 20, 7, 12, 12, 20, 20, 13, 16, 13, 11, 10, 11, 40, 9, 8, 25, 20]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    ws.freeze_panes = "A2"

    # ── Sheet 2: Summary stats ───────────────────────────────────────────────
    ws2 = wb.create_sheet("Summary")
    ws2.column_dimensions["A"].width = 28
    ws2.column_dimensions["B"].width = 14

    def stat_row(label, value, fill=None):
        r = ws2.max_row + 1
        c1 = ws2.cell(row=r, column=1, value=label)
        c2 = ws2.cell(row=r, column=2, value=value)
        c1.font = Font(bold=True)
        if fill:
            c1.fill = fill
            c2.fill = fill
        c2.alignment = Alignment(horizontal="center")

    total   = len(results)
    passed  = sum(1 for r in results if r.passed)
    pass_rate = f"{passed}/{total} ({100*passed//total if total else 0}%)"

    numeric = {attr: [getattr(r, attr) for r in results if getattr(r, attr) is not None]
               for attr in NUMERIC_COLS}

    def fmt(vals, unit=""):
        if not vals:
            return "N/A"
        return f"min={min(vals):.1f} avg={sum(vals)/len(vals):.1f} max={max(vals):.1f}{unit}"

    stat_row("Total runs",            total)
    stat_row("Passed",                pass_rate, GREEN if passed == total else (YELLOW if passed else RED))
    stat_row("", "")
    stat_row("MTTD IDS (s)",                  fmt(numeric["mttd_s"]))
    stat_row("M1 Alert→Decision (s)",         fmt(numeric["t_alert_to_decision_s"]))
    stat_row("M2 Decision→LEAF (ms)",         fmt(numeric["t_decision_to_enforce_ms"]))
    m3_vals = [r.enforcement_correct for r in results if r.enforcement_correct is not None]
    m3_rate = f"{sum(m3_vals)}/{len(m3_vals)} ({100*sum(m3_vals)//len(m3_vals) if m3_vals else 0}%)" if m3_vals else "N/A"
    stat_row("M3 Enforcement Correctness",    m3_rate, GREEN if m3_vals and all(m3_vals) else (YELLOW if m3_vals else None))
    stat_row("Agent internal latency (ms)",   fmt(numeric["enforce_latency_ms"]))
    stat_row("Total E2E (s)",                 fmt(numeric["total_latency_s"]))
    stat_row("Confidence score",              fmt(numeric["confidence"]))
    stat_row("", "")
    outcomes = {}
    for r in results:
        outcomes[r.outcome] = outcomes.get(r.outcome, 0) + 1
    for oc, cnt in sorted(outcomes.items()):
        stat_row(f"Outcome: {oc}", cnt)

    stat_row("", "")
    stat_row("Generated at", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))

    wb.save(path)

# ── Health checks ─────────────────────────────────────────────────────────────

def preflight() -> bool:
    checks = [
        ("IDS API",           f"{IDS_API}/health"),
        ("IDS Agent",         f"{IDS_AGENT}/health"),
        ("Intelligence Layer",f"{INTEL}/health"),
        ("SF API",            f"{SF_API}/api/rules"),
    ]
    ok = True
    for name, url in checks:
        data = http_get(url, timeout=5)
        if data is not None:
            console.print(f"  [green]✓[/] {name}")
        else:
            console.print(f"  [red]✗[/] {name} — [dim]UNREACHABLE ({url})[/]")
            ok = False

    intel = http_get(f"{INTEL}/health") or {}
    dry = intel.get("dry_run", True)
    cb  = (intel.get("circuit_breaker") or {}).get("is_open", False)
    if dry:
        console.print(f"\n  AGENT_DRY_RUN  = [yellow]{dry}[/]  [yellow]⚠ results will be dry_run, not enforced[/]")
    else:
        console.print(f"\n  AGENT_DRY_RUN  = [bold]{dry}[/]  [green]✓ real enforcement[/]")
    if cb:
        console.print("  circuit_breaker = [bold red]OPEN ⚠[/]")
    else:
        console.print("  circuit_breaker = [green]closed ✓[/]")

    mgt_out = console_run("echo MGT_PING_OK", wait=3.0)
    if "MGT_PING_OK" in mgt_out:
        console.print(f"  [green]✓[/] MGT console [dim](port {MGT_CONSOLE_PORT})[/]")
    else:
        console.print("  [red]✗[/] MGT console unreachable — [yellow]run.sh attack trigger will fail[/]")
        ok = False

    scr = console_run("ls /root/scenario/", wait=3.0)
    for script in ("compromise-web.sh", "restore-web.sh"):
        if script in scr:
            console.print(f"  [green]✓[/] [cyan]/root/scenario/{script}[/]")
        else:
            console.print(f"  [red]✗[/] [cyan]/root/scenario/{script}[/] [bold red]MISSING[/]")
            ok = False

    return ok

# ── Main ──────────────────────────────────────────────────────────────────────

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

# ── Configuration (edit here, no CLI args) ──────────────────────────────────
RUNS = 10                                 # number of i.i.d. trials
DURATION_SECONDS = 120                    # per-run timeout in seconds
PAUSE_BETWEEN_RUNS_SECONDS = 10           # cool-down between iterations
DRY_CHECK_ONLY = False                    # True = preflight only, no attack

def _default_output() -> str:
    # Filename: <test_title>_<YYYYMMDD>_<HHMMSS>.xlsx  (date + time of run)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return os.path.join(RESULTS_DIR, f"eval_memory_{ts}.xlsx")

# ── Rich UI helpers ──────────────────────────────────────────────────────────

def _render_header(output_path: str) -> None:
    """Top banner + config panel — printed once at start."""
    title = Text()
    title.append("ZT-EVAL · MEMORY", style="bold magenta")
    title.append("  ", style="")
    title.append("Stateful — `decisions` preserved across runs", style="dim")
    console.print()
    console.print(Panel(
        Align.center(title),
        border_style="magenta",
        padding=(0, 2),
    ))

    cfg = Table.grid(padding=(0, 2))
    cfg.add_column(style="dim")
    cfg.add_column(style="bold")
    cfg.add_row("scenario",       "WEB → DB direct (microsegmentation bypass)")
    cfg.add_row("target SID",     str(TARGET_SID))
    cfg.add_row("attacker IP",    ATTACKER_IP)
    cfg.add_row("runs",           str(RUNS))
    cfg.add_row("run timeout",    f"{DURATION_SECONDS}s")
    cfg.add_row("pause between",  f"{PAUSE_BETWEEN_RUNS_SECONDS}s")
    cfg.add_row("est. duration",  f"~{(DURATION_SECONDS + PAUSE_BETWEEN_RUNS_SECONDS) * RUNS // 60} min")
    cfg.add_row("memory mode",    "[bold magenta]STATEFUL[/] — `decisions` preserved")
    cfg.add_row("output",         output_path)
    console.print(Panel(cfg, title="[bold]config[/]", border_style="dim", padding=(1, 2)))
    console.print()


def _summarize(values: list) -> dict:
    """Return avg/min/max/p95 for a list of numbers (None values skipped)."""
    nums = [v for v in values if v is not None]
    if not nums:
        return {"avg": None, "min": None, "max": None, "p95": None, "n": 0}
    nums_sorted = sorted(nums)
    p95_idx = max(0, math.ceil(len(nums_sorted) * 0.95) - 1)
    return {
        "avg": statistics.mean(nums),
        "min": min(nums),
        "max": max(nums),
        "p95": nums_sorted[p95_idx],
        "n": len(nums),
    }


def _fmt(v, suffix: str = "") -> str:
    if v is None:
        return "[dim]—[/]"
    if isinstance(v, float):
        return f"{v:.2f}{suffix}"
    return f"{v}{suffix}"


def _render_summary(results: List[RunResult]) -> None:
    """Final summary panel + metrics table."""
    n = len(results)
    if n == 0:
        return

    passed = sum(1 for r in results if r.passed)
    pass_rate = passed / n * 100

    # ── Per-run table ──
    runs_tbl = Table(
        title="per-run results",
        title_style="bold",
        show_lines=False,
        header_style="bold magenta",
        border_style="dim",
    )
    runs_tbl.add_column("#",          justify="right", width=3)
    runs_tbl.add_column("status",     width=8)
    runs_tbl.add_column("outcome",    width=10)
    runs_tbl.add_column("MTTD",       justify="right", width=8)
    runs_tbl.add_column("M1 A→D",     justify="right", width=8)
    runs_tbl.add_column("M2 D→LEAF",  justify="right", width=10)
    runs_tbl.add_column("conf",       justify="right", width=6)
    runs_tbl.add_column("checks",     justify="right", width=7)
    runs_tbl.add_column("correct IP", justify="center", width=10)

    for r in results:
        status = "[bold green]PASS[/]" if r.passed else "[bold red]FAIL[/]"
        outcome_color = {"enforced": "green", "dry_run": "yellow", "rejected": "red"}.get(r.outcome, "dim")
        ip_ok = "[green]✓[/]" if r.enforcement_correct else ("[red]✗[/]" if r.enforcement_correct is False else "[dim]—[/]")
        runs_tbl.add_row(
            str(r.run_num),
            status,
            f"[{outcome_color}]{r.outcome}[/]",
            _fmt(r.mttd_s, "s"),
            _fmt(r.t_alert_to_decision_s, "s"),
            _fmt(r.t_decision_to_enforce_ms, "ms"),
            _fmt(r.confidence),
            f"{r.checks_pass}/{r.checks_total}",
            ip_ok,
        )
    console.print(runs_tbl)
    console.print()

    # ── Aggregate metrics ──
    metrics = {
        "MTTD (s)":                [r.mttd_s for r in results],
        "M1 Alert→Decision (s)":   [r.t_alert_to_decision_s for r in results],
        "M2 Decision→LEAF (ms)":   [r.t_decision_to_enforce_ms for r in results],
        "Agent latency (ms)":      [r.enforce_latency_ms for r in results],
        "Total E2E (s)":           [r.total_latency_s for r in results],
        "Confidence":              [r.confidence for r in results],
    }
    metr_tbl = Table(
        title="aggregate metrics",
        title_style="bold",
        header_style="bold magenta",
        border_style="dim",
    )
    metr_tbl.add_column("metric",  style="bold")
    metr_tbl.add_column("avg",     justify="right")
    metr_tbl.add_column("min",     justify="right")
    metr_tbl.add_column("max",     justify="right")
    metr_tbl.add_column("p95",     justify="right")
    metr_tbl.add_column("n",       justify="right", style="dim")

    for name, vals in metrics.items():
        s = _summarize(vals)
        metr_tbl.add_row(
            name,
            _fmt(s["avg"]),
            _fmt(s["min"]),
            _fmt(s["max"]),
            _fmt(s["p95"]),
            str(s["n"]),
        )
    console.print(metr_tbl)
    console.print()

    # ── Headline summary panel ──
    pass_color = "green" if pass_rate == 100 else ("yellow" if pass_rate >= 70 else "red")
    correct_ip = sum(1 for r in results if r.enforcement_correct)
    enforced_or_dry = sum(1 for r in results if r.outcome in ("enforced", "dry_run"))

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column(style="bold")
    summary.add_row("pass rate",        f"[{pass_color}]{passed}/{n} ({pass_rate:.0f}%)[/]")
    summary.add_row("outcome OK",       f"{enforced_or_dry}/{n}  (enforced or dry_run)")
    summary.add_row("src_ip correct",   f"{correct_ip}/{n}")
    console.print(Panel(summary, title="[bold]summary[/]", border_style=pass_color, padding=(1, 2)))

    # ── Memory effect: first run vs last run (the headline metric for this eval) ──
    if n >= 2:
        first, last = results[0], results[-1]
        def _delta(name: str, a, b, unit: str = "", lower_is_better: bool = True):
            if a is None or b is None:
                return f"  {name:<28}  [dim]—[/]"
            delta = b - a
            pct = (delta / a * 100) if a else 0
            arrow = "↓" if delta < 0 else ("↑" if delta > 0 else "→")
            good = (delta < 0) if lower_is_better else (delta > 0)
            color = "green" if good else ("red" if delta != 0 else "dim")
            return f"  {name:<28}  {a:.2f}{unit} → {b:.2f}{unit}   [{color}]{arrow} {abs(pct):.1f}%[/]"

        console.print()
        console.print(Panel(
            "\n".join([
                f"[bold]Run 1 (cold memory) → Run {n} (warm memory)[/]\n",
                _delta("MTTD (s)",            first.mttd_s,                last.mttd_s,                "s"),
                _delta("M1 Alert→Decision (s)", first.t_alert_to_decision_s, last.t_alert_to_decision_s, "s"),
                _delta("Agent latency (ms)",  first.enforce_latency_ms,    last.enforce_latency_ms,    "ms"),
                _delta("Confidence",          first.confidence,            last.confidence,            "", lower_is_better=False),
                "",
                "[dim]Lower latency / higher confidence on later runs ⇒ memory helps.[/]",
            ]),
            title="[bold magenta]memory effect[/]",
            border_style="magenta",
            padding=(1, 2),
        ))


def main():
    output_path = _default_output()
    _render_header(output_path)

    console.print(Rule("preflight", style="dim"))
    if not preflight():
        console.print("[bold red]✗ Preflight failed — fix issues above before running[/]")
        sys.exit(1)
    console.print()

    if DRY_CHECK_ONLY:
        console.print("[bold green]✓ DRY_CHECK_ONLY=True — systems ready, no attack run.[/]\n")
        return

    results: List[RunResult] = []

    for i in range(1, RUNS + 1):
        console.print(Rule(f"run {i}/{RUNS}", style="magenta", characters="─"))
        anchor_ts = reset(i)
        result = run_scenario(i, DURATION_SECONDS, anchor_ts=anchor_ts)
        results.append(result)

        if result.passed:
            badge = "[bold green]PASS ✓[/]"
        else:
            badge = "[bold red]FAIL ✗[/]"
        outcome_color = {"enforced": "green", "dry_run": "yellow", "rejected": "red"}.get(result.outcome, "dim")
        console.print(
            f"  {badge}  outcome=[{outcome_color}]{result.outcome}[/]  "
            f"MTTD=[bold]{_fmt(result.mttd_s, 's')}[/]  "
            f"latency=[bold]{_fmt(result.enforce_latency_ms, 'ms')}[/]  "
            f"conf=[bold]{_fmt(result.confidence)}[/]  "
            f"checks=[bold]{result.checks_pass}/{result.checks_total}[/]"
        )

        cleanup_agent_rules(prefix="    [post-run] ")

        if i < RUNS:
            console.print(f"  [dim]pause {PAUSE_BETWEEN_RUNS_SECONDS}s before next run…[/]\n")
            time.sleep(PAUSE_BETWEEN_RUNS_SECONDS)

    console.print()
    console.print(Rule("results", style="bold magenta"))
    console.print()
    _render_summary(results)

    console.print(Rule("cleanup", style="dim"))
    cleanup_agent_rules(prefix="  ")
    console.print()

    export_excel(results, output_path)
    console.print(f"  [bold green]✓[/] Excel saved → [cyan]{output_path}[/]")

    json_path = output_path.replace(".xlsx", ".json")
    with open(json_path, "w") as f:
        json.dump([r.__dict__ for r in results], f, indent=2, default=str)
    console.print(f"  [bold green]✓[/] JSON  saved → [cyan]{json_path}[/]")
    console.print()


if __name__ == "__main__":
    main()