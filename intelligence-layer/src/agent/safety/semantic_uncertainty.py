"""L2+: Semantic entropy for self-consistency.

Plain action voting (3 runs, 2/3 same action wins) is weak when temperature is low —
runs converge trivially even when LLM is uncertain. Semantic entropy looks beyond
the action label and asks: do the runs agree on the FULL DECISION SHAPE
(action + dst_zone + ttl bucket + src_ip target)?

If runs vote DROP unanimously but propose 3 different src_ip values, that is HIGH
uncertainty even though vote passes. Reject decisions where semantic entropy >
threshold regardless of vote count.

Reference: Farquhar et al. 2024, "Detecting hallucinations in LLMs using semantic entropy"
(simplified to discrete clustering for performance).
"""
import math
from collections import Counter

from ...models.decision import PolicyAction
from ...core.topology import ip_to_zone


def _ttl_bucket(ttl: int) -> str:
    """Coarse-bin TTLs so 3000 vs 3600 don't count as different decisions."""
    if ttl <= 0:
        return "none"
    if ttl < 600:
        return "short"
    if ttl < 1800:
        return "medium"
    if ttl < 3600:
        return "long"
    return "max"


def _decision_signature(intent_dict: dict) -> str:
    """Cluster key: full decision shape, not just action.

    Two intents map to the same signature if they would produce equivalent
    enforcement effects on equivalent network targets.
    """
    src_ip = intent_dict.get("src_ip", "")
    dst_ip = intent_dict.get("dst_ip", "")
    src_zone = ip_to_zone(src_ip) or "unknown"
    dst_zone = ip_to_zone(dst_ip) or "unknown" if dst_ip else "none"
    action = intent_dict.get("action", "UNKNOWN")
    dst_port = intent_dict.get("dst_port", 0)
    ttl_b = _ttl_bucket(int(intent_dict.get("ttl_seconds", 0) or 0))
    return f"{action}|src={src_zone}|dst={dst_zone}|port={dst_port}|ttl={ttl_b}"


def semantic_entropy(intents: list[dict]) -> tuple[float, dict[str, int]]:
    """Shannon entropy over decision signature clusters.

    Args:
        intents: list of raw intent dicts from LLM (multiple self-consistency runs)

    Returns:
        (entropy_bits, cluster_distribution)
        entropy 0.0 = full agreement on shape; high = runs propose different shapes
    """
    if not intents:
        return 0.0, {}
    signatures = [_decision_signature(i) for i in intents]
    counts = Counter(signatures)
    total = sum(counts.values())
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy, dict(counts)


def src_ip_consensus_ratio(intents: list[dict]) -> tuple[float, str]:
    """Fraction of runs agreeing on the same src_ip target.

    Returns (ratio in [0,1], dominant_src_ip). Low ratio with same action vote
    is a strong hallucination signal — agent might block wrong target.
    """
    if not intents:
        return 0.0, ""
    src_ips = [i.get("src_ip", "") for i in intents if i.get("src_ip")]
    if not src_ips:
        return 0.0, ""
    counts = Counter(src_ips)
    dominant, dom_count = counts.most_common(1)[0]
    return dom_count / len(intents), dominant


def evaluate_uncertainty(
    intents: list[dict],
    *,
    entropy_max: float = 1.0,
    src_ip_min_consensus: float = 0.67,
) -> tuple[bool, str]:
    """Compose entropy + src_ip consensus into a single uncertainty verdict.

    Args:
        intents: parsed LLM outputs from N self-consistency runs
        entropy_max: reject if semantic entropy > this many bits
                     (1.0 = ~2 distinct clusters with equal probability)
        src_ip_min_consensus: reject if dominant src_ip ratio < this

    Returns:
        (passed, reason). passed=False with non-empty reason → reject decision.
    """
    if len(intents) <= 1:
        # Single run — entropy meaningless, fall back to caller's logic
        return True, ""

    entropy, clusters = semantic_entropy(intents)
    if entropy > entropy_max:
        return False, (
            f"L2+ semantic entropy {entropy:.2f} bits exceeds {entropy_max} — "
            f"runs disagreed on decision shape: {clusters}"
        )

    consensus, dominant = src_ip_consensus_ratio(intents)
    if consensus < src_ip_min_consensus:
        return False, (
            f"L2+ src_ip consensus {consensus:.0%} below {src_ip_min_consensus:.0%} — "
            f"dominant target was {dominant!r}, possible hallucination"
        )

    return True, ""
