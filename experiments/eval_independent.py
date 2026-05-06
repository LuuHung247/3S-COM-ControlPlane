#!/usr/bin/env python3
"""
eval.py — Zero Trust Intelligence Layer Evaluation
Chạy N lần demo scenario compromise-web, collect metrics, xuất Excel.

Usage:
    python3 eval.py                        # 1 run, 120s, report.xlsx
    python3 eval.py --runs 10              # 10 lần
    python3 eval.py --runs 5 --duration 90 --output results.xlsx
    python3 eval.py --dry-check            # chỉ check health, không chạy attack

Requires: pip3 install openpyxl httpx
"""
import datetime
import json
import os
import socket
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

# ── Config ──────────────────────────────────────────────────────────────────
IDS_API   = os.getenv("IDS_API_URL",   "http://10.10.6.238:8765")
IDS_AGENT = os.getenv("IDS_AGENT_URL", "http://localhost:8766")
INTEL     = os.getenv("INTEL_URL",     "http://localhost:8767")
SF_API    = os.getenv("SF_API_URL",    "http://10.10.6.238:9090")
MGT_CONSOLE_HOST = os.getenv("MGT_CONSOLE_HOST", "10.10.6.238")
MGT_CONSOLE_PORT = int(os.getenv("MGT_CONSOLE_PORT", "5016"))
ATTACKER_IP  = "10.1.100.10"
TARGET_SID   = 9000001
POLL_INTERVAL = 2   # seconds

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
        print(f"{prefix} no agent rules to remove")
        return 0
    deleted = 0
    for rid in rule_ids:
        ok = http_delete(f"{IDS_AGENT}/rules/{rid}")
        status = "✓" if ok else "✗"
        print(f"{prefix} {status} DELETE rule {rid}")
        if ok:
            deleted += 1
    return deleted


def reset(run_num: int) -> float:
    """Reset state between runs. Returns unix timestamp anchor from /alerts/clear."""
    print(f"  [reset] Disarming scenario...")
    console_run("/root/scenario/restore-web.sh", wait=5.0)

    print(f"  [reset] Deleting agent-pushed rules...")
    cleanup_agent_rules(prefix="    ")

    print(f"  [reset] Flushing Redis DB 0 + DB 1 (events buffer) for independence...")
    try:
        for db in ("0", "1"):
            subprocess.run(
                ["docker", "compose", "-f", "/home/dis/deploy/zerotrust/docker-compose.yml",
                 "exec", "-T", "redis", "redis-cli", "-n", db, "FLUSHDB"],
                capture_output=True, timeout=10
            )
        print("    ✓ Redis DB 0 + DB 1 flushed (Eval A independence)")
    except Exception as e:
        print(f"    ✗ Redis flush failed: {e}")

    print(f"  [reset] Truncating workspace decisions table (decisions_history preserved)...")
    try:
        subprocess.run(
            ["docker", "compose", "-f", "/home/dis/deploy/zerotrust/docker-compose.yml",
             "exec", "-T", "postgres", "psql", "-U", "ztuser", "-d", "zerotrust",
             "-c", "TRUNCATE TABLE decisions;"],
            capture_output=True, timeout=10
        )
        print("    ✓ decisions truncated — decisions_history kept for FE display")
    except Exception as e:
        print(f"    ✗ Postgres truncate failed: {e}")

    print(f"  [reset] Resetting intelligence layer state...")
    try:
        req = urllib.request.Request(f"{INTEL}/admin/reset", data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            print(f"    ✓ Rate limiter reset")
    except Exception as e:
        print(f"    ✗ Admin reset failed: {e}")

    anchor_ts = time.time()
    clear = http_get(f"{IDS_API}/alerts/clear")
    if clear and clear.get("cleared_at"):
        try:
            anchor_ts = datetime.datetime.fromisoformat(
                clear["cleared_at"].replace("Z", "+00:00")
            ).timestamp()
            print(f"    ✓ Alert anchor: {clear['cleared_at']}")
        except Exception:
            print(f"    ✓ Alert anchor set (raw): {clear}")
    else:
        print("    (no /alerts/clear — using local timestamp anchor)")

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
    print(f"  [T+0] Triggering compromise-web...")
    t_attack = time.time()
    console_out = console_run("/root/scenario/compromise-web.sh", wait=5.0)
    if "armed" in console_out.lower() or "arming" in console_out.lower():
        print(f"    ✓ Attack armed")
    else:
        print(f"    ? Console output: {console_out[-100:].strip()}")
    # Use anchor from /alerts/clear if available, else fall back to t_attack
    since_ts = anchor_ts if anchor_ts > 0 else t_attack

    # 3. Poll until decision or timeout
    t_first_alert = None
    decision = None
    deadline = t_attack + duration

    print(f"  [poll] Waiting up to {duration}s for Agent decision...")
    while time.time() < deadline:
        elapsed = time.time() - t_attack

        # Check alerts
        if t_first_alert is None:
            alerts = get_alerts_since(since_ts)
            p1 = first_p1_alert(alerts)
            if p1:
                t_first_alert = _alert_ts(p1) or time.time()
                result.mttd_s = round(t_first_alert - t_attack, 1)
                result.alert_count_p1 = sum(
                    1 for a in alerts
                    if (a.get("alert", {}).get("signature_id") or a.get("signature_id")) == TARGET_SID
                )
                print(f"    ✓ SID {TARGET_SID} alert at T+{result.mttd_s}s ({result.alert_count_p1} alerts)")

        # Check decisions
        if decision is None and t_first_alert:
            decisions = get_decisions_since(t_attack - 2)
            if decisions:
                decision = decisions[0]
                result.outcome = decision.get("outcome", "unknown")
                result.enforce_latency_ms = round(decision.get("latency_ms") or 0, 1)
                result.confidence = decision_confidence(decision)
                result.rejection_reason = decision.get("rejection_reason") or ""
                result.dry_run = decision.get("dry_run", True)
                print(f"    ✓ Decision: outcome={result.outcome} latency={result.enforce_latency_ms}ms confidence={result.confidence}")

                # ── Metric 1: Detection-to-Decision wall clock ───────────────
                t_decision_created = None
                try:
                    t_decision_created = datetime.datetime.fromisoformat(
                        decision["created_at"].replace("Z", "+00:00")
                    ).timestamp()
                    result.t_alert_to_decision_s = round(t_decision_created - t_first_alert, 2)
                    print(f"    ✓ [M1] Alert→Decision: {result.t_alert_to_decision_s}s")
                except Exception:
                    pass

                # ── Metric 3: Enforcement correctness ───────────────────────
                src_ip = decision.get("src_ip") or ""
                result.enforcement_correct = (
                    ATTACKER_IP in src_ip or src_ip.startswith(ATTACKER_IP.rstrip("/"))
                ) if src_ip else None
                print(f"    ✓ [M3] Correct src_ip: {result.enforcement_correct} ({src_ip!r})")

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
                            print(f"    ✓ [M2] Rule visible on LEAF at +{result.t_decision_to_enforce_ms}ms after decision")
                            break
                        time.sleep(1)
                    else:
                        print("    ✗ [M2] Rule NOT visible on LEAF after 8s")

                break

        sys.stdout.write(f"\r    elapsed {elapsed:.0f}s ...")
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
    print(f"\n  ✓ Excel saved: {path}")

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
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name} — UNREACHABLE ({url})")
            ok = False

    intel = http_get(f"{INTEL}/health") or {}
    dry = intel.get("dry_run", True)
    cb  = (intel.get("circuit_breaker") or {}).get("is_open", False)
    print(f"\n  AGENT_DRY_RUN  = {dry}  {'⚠ results will be dry_run, not enforced' if dry else '✓ real enforcement'}")
    print(f"  circuit_breaker = {'OPEN ⚠' if cb else 'closed ✓'}")

    mgt_out = console_run("echo MGT_PING_OK", wait=3.0)
    if "MGT_PING_OK" in mgt_out:
        print(f"  ✓ MGT console (port {MGT_CONSOLE_PORT})")
    else:
        print(f"  ✗ MGT console unreachable — run.sh attack trigger will fail")
        ok = False

    scr = console_run("ls /root/scenario/", wait=3.0)
    for script in ("compromise-web.sh", "restore-web.sh"):
        if script in scr:
            print(f"  ✓ /root/scenario/{script}")
        else:
            print(f"  ✗ /root/scenario/{script} MISSING")
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
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return os.path.join(RESULTS_DIR, f"eval_independent_{ts}.xlsx")

def main():
    output_path = _default_output()

    print("\n══════════════════════════════════════════════════════════════")
    print("  Eval A — Independent Runs (Statistical Baseline)")
    print("  Zero Trust Intelligence Layer")
    print("══════════════════════════════════════════════════════════════\n")
    print(f"  RUNS                       = {RUNS}")
    print(f"  DURATION_SECONDS           = {DURATION_SECONDS}")
    print(f"  PAUSE_BETWEEN_RUNS_SECONDS = {PAUSE_BETWEEN_RUNS_SECONDS}")
    print(f"  ATTACKER_IP                = {ATTACKER_IP}")
    print(f"  TARGET_SID                 = {TARGET_SID}")
    print(f"  OUTPUT                     = {output_path}\n")

    print("[Preflight]")
    if not preflight():
        print("\n✗ Preflight failed — fix issues above before running\n")
        sys.exit(1)

    if DRY_CHECK_ONLY:
        print("\n✓ DRY_CHECK_ONLY=True — systems ready, no attack run.\n")
        return

    results: List[RunResult] = []

    for i in range(1, RUNS + 1):
        print(f"══ Run {i}/{RUNS} ════════════════════════════════════════════")
        anchor_ts = reset(i)
        result = run_scenario(i, DURATION_SECONDS, anchor_ts=anchor_ts)
        results.append(result)

        status = "PASS ✓" if result.passed else "FAIL ✗"
        print(f"  [{status}] outcome={result.outcome} MTTD={result.mttd_s}s "
              f"latency={result.enforce_latency_ms}ms confidence={result.confidence} "
              f"checks={result.checks_pass}/{result.checks_total}")

        print(f"  [post-run] cleaning agent rules pushed in this run...")
        cleanup_agent_rules(prefix="    ")

        if i < RUNS:
            print(f"  [pause] {PAUSE_BETWEEN_RUNS_SECONDS}s before next run...\n")
            time.sleep(PAUSE_BETWEEN_RUNS_SECONDS)

    print("\n══ Results ══════════════════════════════════════════════════════")
    passed = sum(1 for r in results if r.passed)
    print(f"  {passed}/{len(results)} runs PASSED\n")

    print("[Final cleanup]")
    cleanup_agent_rules(prefix="  ")
    print()

    export_excel(results, output_path)

if __name__ == "__main__":
    main()
