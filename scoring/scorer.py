"""Rule-based IPsec security scoring; unknown observations are not guessed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_RULES = ROOT / "scoring" / "rules.yaml"


def score_capture(
    ike_facts: dict[str, Any], rules_path: str = "scoring/rules.yaml"
) -> dict[str, Any]:
    """Apply configured penalties and the explicit critical-issue score cap."""
    path = Path(rules_path)
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        raise FileNotFoundError(f"Scoring rules file does not exist: {path}")
    with path.open(encoding="utf-8") as rules_file:
        configuration = yaml.safe_load(rules_file)
    rules = configuration.get("rules") if isinstance(configuration, dict) else None
    if not isinstance(rules, list):
        raise ValueError(f"Invalid scoring rules document: {path}")

    score = 100
    findings = []
    hard_cap = False
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Every scoring rule must be a mapping")
        rule_id = rule.get("id")
        field = rule.get("check_field")
        if not isinstance(rule_id, str) or not isinstance(field, str):
            raise ValueError("Every scoring rule needs string id and check_field")
        value = ike_facts.get(field)
        is_triggered = False
        if rule_id == "long_sa_lifetime":
            is_triggered = value is None or (
                isinstance(value, (int, float)) and value > 86400
            )
        elif value is not None:
            bad_values = rule.get("bad_values") or []
            is_triggered = any(
                value == bad
                or (
                    isinstance(value, str)
                    and isinstance(bad, str)
                    and value.casefold() == bad.casefold()
                )
                for bad in bad_values
            )
        if not is_triggered:
            continue
        penalty = rule.get("score_penalty")
        if not isinstance(penalty, int) or penalty < 0:
            raise ValueError(f"Invalid score_penalty in scoring rule {rule_id}")
        score -= penalty
        hard_cap = hard_cap or rule_id in {"weak_encryption", "no_auth_detected"}
        findings.append(
            {
                "id": rule_id,
                "severity": rule.get("severity", "unknown"),
                "message": rule.get("message", ""),
                "field": field,
                "observed_value": value,
                "category": rule.get("category", "Session Management"),
            }
        )
    score = max(0, score)
    if hard_cap:
        score = min(score, 20)
    threat_matrix = [
        {
            "category": finding["category"],
            "severity": finding["severity"],
            "description": finding["message"],
        }
        for finding in findings
    ]
    return {"risk_score": score, "findings": findings, "threat_matrix": threat_matrix}
