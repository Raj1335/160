"""Policy helpers for IPsec security scoring."""

from __future__ import annotations

from typing import Iterable


def score_caps(score: int, triggered_rule_ids: Iterable[str]) -> int:
    """Apply the explicit hard cap for weak encryption or failed auth."""
    if any(
        rule_id in {"weak_encryption", "encryption_des", "no_auth_detected"}
        for rule_id in triggered_rule_ids
    ):
        return min(score, 20)
    return score


def grade_for_score(score: int) -> str:
    """Map a numeric security score to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    if score >= 50:
        return "E"
    return "F"
