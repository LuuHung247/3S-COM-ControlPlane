"""LLM compilation of the knowledge base into a verified response program.

compile_program() gives the model the architecture documents (zones, policy matrix,
signature catalogue with its prose, invariants, assets) and the program language, and
asks for one program covering the whole fabric. The verifier then checks the program on
every point of the input domain; violations go back to the model as counterexamples and
it repairs the program (counterexample-guided, bounded rounds). Only a program that
passes verification is ever marked usable; the artefact records the knowledge-base
digest it was compiled from, the model, the rounds and the token cost.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import structlog

from .dsl import Program, ProgramError
from .kb import KBSnapshot
from .dsl import Ensemble
from .verifier import (AUTO_ENFORCE_CONFIDENCE, HOST_SCOPE_TTL_MAX, OVERRIDE_CONFIDENCE,
                       behaviour_summary, verify)
from ..core.invariants import TTL_MAX_SECONDS, TTL_MIN_SECONDS

log = structlog.get_logger()

MAX_REPAIR_ROUNDS = 3

REVIEW = """Below is what your program decides for every alert the fabric can raise from an ordinary
(unprotected, in-fabric) source, grouped by signature and policy verdict. Review it signature by
signature against the knowledge base: the documented response and any condition attached to it,
the severity, the zones the signature concerns, what blocking would cost. Wherever the behaviour
does not follow from the knowledge base, change the program; where an alert is decidable from the
knowledge base but the program abstains, decide it. Keep the hard constraints.

{summary}

Return the complete revised program (all rules), JSON only."""

SYSTEM = """You are the response-policy compiler of a Zero Trust microsegmented data-centre fabric.
You read the architecture knowledge base and write ONE response program that decides, for every
IDS alert the fabric can raise, whether the agent blocks the alert source, only logs, or abstains
and hands the alert to a human-supervised runtime analyst. The program runs without you: alerts
are answered by the program alone, so everything you know about this fabric must be in it.

Objectives, in priority order:
1. Never harm the fabric: obey every hard constraint listed below.
2. Contain malicious activity the knowledge base identifies as needing a response: traffic that
   violates the Zero Trust policy, and abuse carried inside a connection the policy permits when a
   signature's documented semantics say the content or behaviour itself is malicious.
3. Do not cut legitimate traffic: informational, reconnaissance-only and audit signatures, and
   anything on a permitted path without documented abuse semantics, are logged, not blocked.
4. Prefer the narrowest scope that contains the threat; widen only when the knowledge base
   justifies it.
5. When the knowledge base does not determine the answer, abstain. Abstaining is always safe.
Read the prose of each signature, zone and asset, not only the structured fields.
"""

LANGUAGE = """## Program language
A program is {"rules": [...], "notes": "..."}. Rules are evaluated in order; the FIRST rule whose
conditions all hold decides. An alert no rule matches is "abstain". Each rule:
{"id": "R1",
 "when": {                      # every listed condition must hold; omit a key to not constrain it
   "sids": [int, ...],          # alert signature id is one of these
   "sid_known": bool,           # false = signature absent from the catalogue
   "severity_min": int, "severity_max": int,   # alert severity 1 (critical) .. 4 (audit)
   "src_zones": [zone, ...], "dst_zones": [zone, ...],   # zone names below, or "EXTERNAL"
   "verdicts": ["ALLOW"|"DENY"|"INTRA"|"EXTERNAL", ...], # policy-matrix verdict of (src_zone,dst_zone);
                                                        # INTRA = same zone, EXTERNAL = either side outside the fabric
   "src_protected": bool,       # alert source is in the never-block set
   "prior_alerts_min": int,     # earlier alerts from the same source in the 10-minute window (0 or 1+)
   "distinct_targets_min": int, # other destinations that source was alerted on in the window (0, 1, 2+)
   "ports_on_target_min": int   # other ports on this same destination already alerted (0 or 1+)
 },
 "then": {"action": "DROP"|"log_only"|"abstain",
          "scope": "flow"|"pair"|"host",   # flow = src->dst:port, pair = src->dst all ports, host = all traffic from src
          "ttl_seconds": int, "confidence": float},
 "rationale": "why, citing the knowledge base",
 "kb_refs": ["SID 9000001", "policy-matrix WEB->DB-OLTP", "zones.md DB-OLTP", ...]}
The blocked address is always the alert source; you cannot choose another target.

## Hard constraints (a program violating any of them on ANY input is rejected)
- No DROP when src_protected is true or the source zone is EXTERNAL.
- DROP only for severity 1 or 2, with confidence >= @AUTO@.
- DROP ttl_seconds in [@TMIN@, @TMAX@].
- Host scope only for severity 1, with ttl_seconds <= @HOST_TTL@.
- A DROP where the verdict is ALLOW must be flow scope, ttl_seconds <= @HOST_TTL@, confidence >= @OVR@.
- No DROP for signatures absent from the catalogue (sid_known false): abstain or log_only.
- Every DROP rule has a rationale and at least one kb_refs entry; cite only signatures that exist.
Put protective rules (protected source, external source) FIRST so later rules cannot override them.
Output ONLY the JSON program."""
for _k, _v in {"AUTO": AUTO_ENFORCE_CONFIDENCE, "TMIN": TTL_MIN_SECONDS, "TMAX": TTL_MAX_SECONDS,
               "HOST_TTL": HOST_SCOPE_TTL_MAX, "OVR": OVERRIDE_CONFIDENCE}.items():
    LANGUAGE = LANGUAGE.replace(f"@{_k}@", str(_v))


def _kb_message(kb: KBSnapshot) -> str:
    parts = [f"## Knowledge base (snapshot {kb.digest})",
             f"Zones: {', '.join(kb.zone_names())}. Signatures in the catalogue: {len(kb.sids)}."]
    for name, text in kb.texts.items():
        parts.append(f"\n### FILE {name}\n{text}")
    return "\n".join(parts)


def _extract_json(text: str) -> dict:
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ProgramError("model output contains no JSON object")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ProgramError(f"model output is not valid JSON: {exc}") from exc


class Compiler:
    """Holds the model endpoint; each call is retried on transport faults and HTTP
    429/5xx so a provider hiccup never becomes a compile failure."""

    def __init__(self, api_key: str, base_url: str, model: str, *, temperature: float = 0.0,
                 max_tokens: int = 16000, reasoning_effort: str = "medium",
                 timeout_s: float = 240.0, attempts: int = 5) -> None:
        self.api_key, self.base_url, self.model = api_key, base_url.rstrip("/"), model
        self.temperature, self.max_tokens = temperature, max_tokens
        self.reasoning_effort, self.timeout_s, self.attempts = reasoning_effort, timeout_s, attempts

    @classmethod
    def from_settings(cls, settings, **kw) -> "Compiler":
        return cls(settings.llm_primary_api_key, settings.llm_primary_base_url,
                   settings.llm_primary_model, **kw)

    async def _call(self, messages: list[dict]) -> tuple[str, dict, float]:
        payload = {"model": self.model, "messages": messages, "temperature": self.temperature,
                   "max_tokens": self.max_tokens, "response_format": {"type": "json_object"}}
        if self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        last: Exception | None = None
        for attempt in range(self.attempts):
            t0 = time.monotonic()
            try:
                async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                    resp = await client.post(f"{self.base_url}/chat/completions", json=payload,
                                             headers={"Authorization": f"Bearer {self.api_key}"})
                if resp.status_code == 429 or resp.status_code >= 500:
                    raise httpx.HTTPStatusError(f"HTTP {resp.status_code}", request=resp.request,
                                                response=resp)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"].get("content") or ""
                return content, data.get("usage", {}), time.monotonic() - t0
            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                if code not in (429,) and code < 500:
                    raise                                   # 4xx other than 429: not transient
                last = exc
            except (httpx.TransportError, KeyError, ValueError) as exc:
                last = exc
            delay = min(60, 5 * 2 ** attempt)
            log.warning("compiler_llm_retry", attempt=attempt + 1, error=str(last)[:120], delay_s=delay)
            await asyncio.sleep(delay)
        raise RuntimeError(f"compiler LLM unavailable after {self.attempts} attempts: {last}")

    async def _converge(self, kb: KBSnapshot, messages: list[dict], max_rounds: int,
                        rounds: list, usage_total: dict, stage: str):
        """Ask, verify, feed counterexamples back; returns (program, report, content)."""
        program = report = None
        content = ""
        for rnd in range(max_rounds + 1):
            content, usage, latency = await self._call(messages)
            for k in usage_total:
                usage_total[k] += int(usage.get(k) or 0)
            entry = {"stage": stage, "round": rnd, "latency_s": round(latency, 2),
                     "prompt_tokens": usage.get("prompt_tokens"),
                     "completion_tokens": usage.get("completion_tokens")}
            try:
                program = Program.from_json(_extract_json(content), kb.zone_names())
            except ProgramError as exc:
                entry["parse_error"] = str(exc)
                rounds.append(entry)
                feedback = [f"The program could not be parsed: {exc}"]
                program = report = None
            else:
                report = verify(kb, program)
                entry.update(report.summary())
                rounds.append(entry)
                if report.ok:
                    break
                feedback = report.counterexamples()
            if rnd == max_rounds:
                break
            messages = messages + [
                {"role": "assistant", "content": content[:60000]},
                {"role": "user", "content": "The verifier rejected the program. Counterexamples:\n- "
                 + "\n- ".join(feedback)
                 + "\n\nReturn the complete corrected program (all rules), JSON only."}]
        return program, report, content

    async def compile_one(self, kb: KBSnapshot, max_rounds: int = MAX_REPAIR_ROUNDS,
                          review: bool = True, rounds: list | None = None,
                          usage_total: dict | None = None):
        """Draft -> verify/repair -> (optional) semantic self-review -> verify/repair."""
        rounds = rounds if rounds is not None else []
        usage_total = usage_total if usage_total is not None else {"prompt_tokens": 0, "completion_tokens": 0}
        base = [{"role": "system", "content": SYSTEM + "\n" + LANGUAGE},
                {"role": "user", "content": _kb_message(kb) + "\n\nWrite the response program for this fabric."}]
        program, report, content = await self._converge(kb, base, max_rounds, rounds, usage_total, "draft")
        if review and program is not None and report is not None and report.ok:
            msgs = base + [{"role": "assistant", "content": json.dumps(program.to_json())},
                           {"role": "user", "content": REVIEW.format(summary=behaviour_summary(kb, program))}]
            revised, rrep, _ = await self._converge(kb, msgs, max_rounds, rounds, usage_total, "review")
            if revised is not None and rrep is not None and rrep.ok:
                program, report = revised, rrep
        return program, report

    async def compile(self, kb: KBSnapshot, max_rounds: int = MAX_REPAIR_ROUNDS,
                      samples: int = 1, review: bool = True) -> dict:
        """One program (samples=1) or a majority ensemble of independently compiled,
        individually verified programs; the ensemble is verified again as a whole."""
        rounds, usage_total = [], {"prompt_tokens": 0, "completion_tokens": 0}
        t_start = time.monotonic()
        members = []
        for i in range(samples):
            prog, rep = await self.compile_one(kb, max_rounds, review, rounds, usage_total)
            if rounds:
                rounds[-1]["sample"] = i
            if prog is not None and rep is not None and rep.ok:
                members.append(prog)
        final: Program | Ensemble | None
        if samples == 1:
            final = members[0] if members else None
        else:
            final = Ensemble(members) if len(members) >= 3 else None
        report = verify(kb, final) if final is not None else None
        return {
            "compiled_at": datetime.now(timezone.utc).isoformat(),
            "kb_root": str(kb.root), "kb_digest": kb.digest,
            "model": self.model, "reasoning_effort": self.reasoning_effort,
            "temperature": self.temperature, "samples": samples, "review": review,
            "verified": bool(report and report.ok),
            "rounds": rounds, "usage": usage_total,
            "compile_seconds": round(time.monotonic() - t_start, 1),
            "verification": report.summary() if report else None,
            "program": final.to_json() if isinstance(final, Program) else None,
            "ensemble": [p.to_json() for p in final.programs] if isinstance(final, Ensemble) else None,
        }


def save(artifact: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2))
    return path
