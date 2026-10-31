"""Harness-side protection against infrastructure faults.

A decision the agent did not get to make — transport error, HTTP 5xx, provider rate
limit or timeout, enforcement backend unreachable — is not a result. post_alert()
retries such cases with backoff after a health check, and raises InfraError when they
persist; callers record the case as "infra_error" and re-run it, never as a miss.
Every infrastructure fault leaves a container-log snapshot next to the results.
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

INTEL = "http://localhost:8767"
IDS_AGENT = "http://localhost:8766"
LOG_DIR = Path(__file__).resolve().parents[1] / "results" / "_infra_logs"

# Rejection/error text that means the pipeline could not decide, not that it decided.
INFRA_MARKERS = ("429", "Too Many Requests", "LLM failed", "ReadTimeout", "ConnectTimeout",
                 "ConnectError", "timed out", "unreachable", "HTTP 5", "Internal Server Error",
                 "circuit breaker", "Circuit breaker", "unhandled:")


class InfraError(RuntimeError):
    pass


def _req(method: str, url: str, data: dict | None = None, timeout: float = 15):
    """One HTTP call. Reads (GET/DELETE) are retried on transport faults and on bodies
    that are not complete JSON or a 5xx (ids-agent /rules can return a cut-off body or
    503 while the Secure Framework is mid-update); POST is never retried here."""
    body = json.dumps(data).encode() if data is not None else None
    tries = 1 if method == "POST" else 4
    for i in range(tries):
        req = urllib.request.Request(url, data=body, method=method,
                                     headers={"Content-Type": "application/json"} if body else {})
        try:
            return json.loads(urllib.request.urlopen(req, timeout=timeout).read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code < 500 or i + 1 == tries:
                raise
            time.sleep(1 + i)
        except (json.JSONDecodeError, urllib.error.URLError, OSError, ValueError):
            if i + 1 == tries:
                raise
            time.sleep(1 + i)


def capture_logs(tag: str, since: str = "15m") -> str:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{tag}.log"
    try:
        out = subprocess.run(["docker", "logs", "--since", since, "intelligence-layer"],
                             capture_output=True, text=True, timeout=60)
        path.write_text(out.stdout + out.stderr)
    except Exception as exc:
        path.write_text(f"log capture failed: {exc}")
    return str(path)


def preflight(want_compiled: bool | None = None, want_dry_run: bool | None = None,
              wait_s: float = 120) -> dict:
    """Wait until the service is healthy (and in the requested mode); raise otherwise."""
    deadline, last = time.time() + wait_s, "no response"
    while time.time() < deadline:
        try:
            h = _req("GET", f"{INTEL}/health", timeout=5)
            c = _req("GET", f"{INTEL}/admin/compiled", timeout=5)
            problems = []
            if h.get("status") != "ok":
                problems.append(f"status={h.get('status')}")
            if h.get("ids_agent") != "connected":
                problems.append(f"ids_agent={h.get('ids_agent')}")
            if want_dry_run is not None and bool(h.get("dry_run")) != want_dry_run:
                problems.append(f"dry_run={h.get('dry_run')}")
            if want_compiled is True and not (c.get("enabled") and c.get("status") == "active"):
                problems.append(f"compiled={c.get('status')}")
            if want_compiled is False and c.get("enabled"):
                problems.append("compiled policy enabled")
            if not problems:
                return {"health": h, "compiled": c}
            last = ", ".join(problems)
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(3)
    raise InfraError(f"preflight failed: {last}")


def is_infra(r: dict) -> bool:
    if r.get("outcome") == "error":
        return True
    if r.get("outcome") == "rejected":
        reason = r.get("rejection_reason") or ""
        return any(m in reason for m in INFRA_MARKERS)
    return False


def post_alert(alert: dict, *, attempts: int = 4, timeout: float = 150, between=None,
               tag: str = "case") -> dict:
    """POST one alert; retry infrastructure faults. `between()` runs before each retry
    (e.g. remove any rule a half-finished attempt pushed, reset counters)."""
    last = ""
    for attempt in range(attempts):
        try:
            r = _req("POST", f"{INTEL}/alerts", {"data": alert}, timeout=timeout)
            if not is_infra(r):
                r["_attempts"] = attempt + 1
                return r
            last = f"{r.get('outcome')}: {(r.get('rejection_reason') or '')[:160]}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
        capture_logs(f"{tag}_attempt{attempt + 1}")
        time.sleep(min(90, 15 * (attempt + 1)))
        preflight(wait_s=180)
        if between is not None:
            between()
    raise InfraError(f"{tag}: no decision after {attempts} attempts ({last}); logs in {LOG_DIR}")


def agent_rules() -> list[dict]:
    d = _req("GET", f"{IDS_AGENT}/rules", timeout=15)
    return [u.get("val", {}) for ld in (d.get("leaves") or {}).values()
            for n in (ld.get("rules") or {}).get("notification", []) for u in n.get("update", [])
            if u.get("val", {}).get("source") == "agent"]


def clean_rules() -> int:
    n = 0
    for v in agent_rules():
        rid = v.get("rule-id")
        if rid:
            try:
                _req("DELETE", f"{IDS_AGENT}/rules/{rid}", timeout=15)
                n += 1
            except Exception:
                pass
    return n


def reset() -> None:
    _req("POST", f"{INTEL}/admin/reset", {}, timeout=15)
