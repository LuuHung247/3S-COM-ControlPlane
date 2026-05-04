"""L7: Confidence gate — route decisions by confidence score."""
from enum import Enum


class ConfidenceOutcome(str, Enum):
    ENFORCE = "enforce"
    ENFORCE_AND_NOTIFY = "enforce_and_notify"
    HOLD = "hold"
    REJECT = "reject"


def evaluate_confidence(
    confidence: float,
    auto_enforce_threshold: float = 0.85,
    notify_threshold: float = 0.70,
    hold_threshold: float = 0.50,
) -> tuple[ConfidenceOutcome, str]:
    """
    Return (outcome, reason).
    Thresholds (exclusive lower bound):
      ≥ auto_enforce_threshold  → ENFORCE
      ≥ notify_threshold        → ENFORCE_AND_NOTIFY
      ≥ hold_threshold          → HOLD (manual review queue)
      < hold_threshold          → REJECT
    """
    if confidence >= auto_enforce_threshold:
        return ConfidenceOutcome.ENFORCE, ""
    if confidence >= notify_threshold:
        return ConfidenceOutcome.ENFORCE_AND_NOTIFY, (
            f"L7: confidence={confidence:.2f} < {auto_enforce_threshold} — enforcing with notification"
        )
    if confidence >= hold_threshold:
        return ConfidenceOutcome.HOLD, (
            f"L7: confidence={confidence:.2f} < {notify_threshold} — placed in review queue"
        )
    return ConfidenceOutcome.REJECT, (
        f"L7: confidence={confidence:.2f} < {hold_threshold} — rejected (too uncertain)"
    )
