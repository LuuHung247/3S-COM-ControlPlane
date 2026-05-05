"""L2: Self-consistency — run reasoning N times, vote on action. Reject on disagreement.

When n_runs=1, this is effectively a single LLM call with retry on transient failures
(Cerebras 400 generation_error happens stochastically with complex schemas).

Beyond simple action voting, also evaluates semantic entropy across runs to catch
the case where runs agree on action but disagree on FULL DECISION SHAPE
(different src_ip targets, different dst_zones, different TTLs) — strong hallucination signal.
"""
import asyncio
from typing import Any

import structlog

from ..llm.interface import LLMClient
from .semantic_uncertainty import evaluate_uncertainty

log = structlog.get_logger()


async def self_consistency_vote(
    client: LLMClient,
    messages: list[dict[str, str]],
    schema: dict[str, Any],
    n_runs: int = 3,
    min_agree: int = 2,
    max_retries_per_run: int = 2,
) -> tuple[dict[str, Any] | None, str]:
    """
    Run chat_json n_runs times. Return (winning_result, error).
    error is non-empty if agreement threshold not met.

    Each run retries up to max_retries_per_run on transient LLM failures
    (e.g., Cerebras 400 tool_call parser glitch). Single failed run is logged.
    """
    votes: dict[str, list[dict[str, Any]]] = {}
    last_error: str = ""

    for run_idx in range(n_runs):
        for attempt in range(max_retries_per_run + 1):
            try:
                result = await client.chat_json(messages=messages, schema=schema)
                action = result.get("action", "UNKNOWN")
                votes.setdefault(action, []).append(result)
                break
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {str(exc)[:120]}"
                if attempt < max_retries_per_run:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                log.warning("self_consistency_run_failed",
                            run=run_idx, attempts=attempt + 1, error=last_error)

    if not votes:
        return None, f"L2: All self-consistency runs failed (last: {last_error})"

    best_action = max(votes, key=lambda a: len(votes[a]))
    best_count = len(votes[best_action])

    if best_count < min_agree:
        actions_summary = {a: len(v) for a, v in votes.items()}
        return None, (
            f"L2: Self-consistency failed — no action reached {min_agree}/{n_runs} agreement. "
            f"Votes: {actions_summary}"
        )

    # L2+: Semantic entropy — catch agreement on action but disagreement on shape.
    # Only meaningful when n_runs >= 2; for n_runs=1 this is a no-op.
    all_results = [r for action_runs in votes.values() for r in action_runs]
    passed, uncertainty_reason = evaluate_uncertainty(all_results)
    if not passed:
        log.warning("self_consistency_uncertainty_reject", reason=uncertainty_reason)
        return None, uncertainty_reason

    return votes[best_action][-1], ""
