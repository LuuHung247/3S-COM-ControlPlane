#!/usr/bin/env python3
"""Compile a knowledge-base directory into a verified response program.

Usage: intelligence-layer/.venv/bin/python compiled_policy/compile_kb.py KB_DIR OUT.json
       [--effort low|medium|high] [--rounds N] [--temperature T] [--samples K] [--no-review]
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

IL = Path(__file__).resolve().parents[2] / "intelligence-layer"
sys.path.insert(0, str(IL))
from src.compiler.compiler import Compiler, save  # noqa: E402
from src.compiler.kb import KBSnapshot  # noqa: E402
from src.config import Settings  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kb_dir")
    ap.add_argument("out")
    ap.add_argument("--effort", default="medium")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--samples", type=int, default=1)
    ap.add_argument("--no-review", action="store_true")
    a = ap.parse_args()
    kb = KBSnapshot.load(a.kb_dir)
    comp = Compiler.from_settings(Settings(_env_file=str(IL / ".env")), reasoning_effort=a.effort,
                                   temperature=a.temperature)
    art = asyncio.run(comp.compile(kb, max_rounds=a.rounds, samples=a.samples, review=not a.no_review))
    save(art, a.out)
    print(json.dumps({k: art[k] for k in ("kb_digest", "model", "verified", "usage", "compile_seconds")}))
    for r in art["rounds"]:
        print(" ", {k: r.get(k) for k in ("sample", "stage", "round", "ok", "latency_s", "prompt_tokens", "completion_tokens",
                                          "violation_kinds", "violating_points", "coverage", "parse_error")})


if __name__ == "__main__":
    main()
