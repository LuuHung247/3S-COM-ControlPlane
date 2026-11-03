#!/usr/bin/env python3
"""Pool of independent syntheses with every intermediate candidate kept.

Each run is one draft -> verify/repair -> self-review -> verify/repair pass of the
deployed compiler (same prompts, model, rounds), but the candidate program of every
round and the verifier's counterexamples grouped by check are stored, so the arms of
the synthesis ablation can be read off one pool:
  one-shot      = the round-0 draft, deployed whether or not it verifies
  repair only   = the converged draft (verified, or discarded after the round budget)
  repair+review = the final program of the run
Ensembles of size k are formed afterwards from the verified finals (synth_eval.py).

Usage: intelligence-layer/.venv/bin/python compiled_policy/synth_pool.py KB_DIR OUT_DIR
       --runs N [--temperature T] [--parallel P] [--start I]
"""
import argparse
import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path

IL = Path(__file__).resolve().parents[2] / "intelligence-layer"
sys.path.insert(0, str(IL))
from src.compiler import compiler as C  # noqa: E402
from src.compiler.dsl import Program, ProgramError  # noqa: E402
from src.compiler.kb import KBSnapshot  # noqa: E402
from src.compiler.verifier import behaviour_summary, verify  # noqa: E402
from src.config import Settings  # noqa: E402


def by_check(report) -> dict:
    """Violating inputs and counterexamples per check (I3, I4, I5, G1 catalog, I6 citation)."""
    pts, kinds = Counter(), Counter()
    for (_rid, msg), (n, _f) in report.violations.items():
        check = msg.split(":")[0]
        pts[check] += n
        kinds[check] += 1
    for _rid, msg in report.provenance:
        kinds[msg.split(":")[0]] += 1
    return {"points": dict(pts), "counterexamples": dict(kinds)}


class LoggingCompiler(C.Compiler):
    async def _converge(self, kb, messages, max_rounds, rounds, usage_total, stage):
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
                program = Program.from_json(C._extract_json(content), kb.zone_names())
            except ProgramError as exc:
                entry["parse_error"] = str(exc)
                rounds.append(entry)
                feedback = [f"The program could not be parsed: {exc}"]
                program = report = None
            else:
                report = verify(kb, program)
                entry.update(report.summary())
                entry["by_check"] = by_check(report)
                entry["candidate"] = program.to_json()
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


async def one_run(comp, kb, i, out_dir, sem):
    path = out_dir / f"run_{i:03d}.json"
    if path.exists():
        return
    async with sem:
        rounds, usage = [], {"prompt_tokens": 0, "completion_tokens": 0}
        t0 = time.monotonic()
        try:
            prog, rep = await comp.compile_one(kb, C.MAX_REPAIR_ROUNDS, True, rounds, usage)
        except Exception as exc:                      # recorded, the run is repeated later
            print(f"run {i}: error {str(exc)[:120]}", flush=True)
            return
        art = {"run": i, "kb_digest": kb.digest, "model": comp.model, "temperature": comp.temperature,
               "reasoning_effort": comp.reasoning_effort, "max_rounds": C.MAX_REPAIR_ROUNDS,
               "seconds": round(time.monotonic() - t0, 1), "usage": usage, "rounds": rounds,
               "verified": bool(rep and rep.ok),
               "final": prog.to_json() if prog is not None and rep is not None and rep.ok else None}
        path.write_text(json.dumps(art))
        r0 = rounds[0]
        print(f"run {i}: r0_ok={r0.get('ok')} ce0={r0.get('violation_kinds')} rounds={len(rounds)} "
              f"verified={art['verified']} tok={sum(usage.values())} {art['seconds']}s", flush=True)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kb_dir")
    ap.add_argument("out_dir")
    ap.add_argument("--runs", type=int, required=True)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--parallel", type=int, default=3)
    a = ap.parse_args()
    kb = KBSnapshot.load(a.kb_dir)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    comp = LoggingCompiler.from_settings(Settings(_env_file=str(IL / ".env")), reasoning_effort="medium",
                                         temperature=a.temperature)
    sem = asyncio.Semaphore(a.parallel)
    await asyncio.gather(*(one_run(comp, kb, i, out, sem) for i in range(a.start, a.start + a.runs)))


if __name__ == "__main__":
    asyncio.run(main())
