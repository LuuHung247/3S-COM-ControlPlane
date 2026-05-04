"""L2: Self-consistency — run reasoning N times, vote on action. Reject on disagreement."""
from typing import Any

from ..llm.interface import LLMClient


async def self_consistency_vote(
    client: LLMClient,
    messages: list[dict[str, str]],
    schema: dict[str, Any],
    n_runs: int = 3,
    min_agree: int = 2,
) -> tuple[dict[str, Any] | None, str]:
    """
    Run chat_json n_runs times. Return (winning_result, error).
    error is non-empty if agreement threshold not met.
    winning_result is the most common action's last response.
    """
    votes: dict[str, list[dict[str, Any]]] = {}

    for _ in range(n_runs):
        try:
            result = await client.chat_json(messages=messages, schema=schema)
            action = result.get("action", "UNKNOWN")
            votes.setdefault(action, []).append(result)
        except Exception:
            pass

    if not votes:
        return None, "L2: All self-consistency runs failed"

    best_action = max(votes, key=lambda a: len(votes[a]))
    best_count = len(votes[best_action])

    if best_count < min_agree:
        actions_summary = {a: len(v) for a, v in votes.items()}
        return None, (
            f"L2: Self-consistency failed — no action reached {min_agree}/{n_runs} agreement. "
            f"Votes: {actions_summary}"
        )

    # Return the last response for the winning action
    return votes[best_action][-1], ""
