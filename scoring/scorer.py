"""Rule-based IPsec security scoring; unknown observations are not guessed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from scoring.policy import grade_for_score, score_caps

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
    rule_results = []
    triggered_rule_ids = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Every scoring rule must be a mapping")
        rule_id = rule.get("id")
        field = rule.get("check_field")
        if not isinstance(rule_id, str) or not isinstance(field, str):
            raise ValueError("Every scoring rule needs string id and check_field")
        source_field = field
        value = ike_facts.get(field)
        if value is None and field == "encryption_algorithm":
            source_field = "esp_encryption_algorithm"
            value = ike_facts.get(source_field)
        elif value is None and field == "integrity_algorithm":
            source_field = "esp_integrity_algorithm"
            value = ike_facts.get(source_field)
        source = ike_facts.get("fact_sources", {}).get(
            source_field, "capture parsing"
        )
        is_triggered = False
        status = "NOT OBSERVABLE" if value is None else "PASS"
        if value is not None:
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
            threshold = rule.get("gt")
            if threshold is not None:
                if not isinstance(threshold, (int, float)):
                    raise ValueError(f"Invalid gt threshold in scoring rule {rule_id}")
                is_triggered = is_triggered or (
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and value > threshold
                )
        if not is_triggered:
            rule_results.append(
                {
                    "id": rule_id,
                    "field": field,
                    "status": status,
                    "observed_value": value,
                    "source": source,
                }
            )
            continue
        penalty = rule.get("score_penalty")
        if not isinstance(penalty, int) or penalty < 0:
            raise ValueError(f"Invalid score_penalty in scoring rule {rule_id}")
        score -= penalty
        triggered_rule_ids.append(rule_id)
        rule_results.append(
            {
                "id": rule_id,
                "field": field,
                "status": "FAIL",
                "observed_value": value,
                "source": source,
            }
        )
        findings.append(
            {
                "id": rule_id,
                "severity": rule.get("severity", "unknown"),
                "message": rule.get("message", ""),
                "field": field,
                "observed_value": value,
                "source": source,
                "category": rule.get("category", "Session Management"),
            }
        )
    score = score_caps(max(0, score), triggered_rule_ids)
    threat_matrix = [
        {
            "category": finding["category"],
            "severity": finding["severity"],
            "description": finding["message"],
        }
        for finding in findings
    ]
    security_score = score
    grade = grade_for_score(security_score)
    coverage = {
        "total": len(rule_results),
        "observed": sum(
            result["status"] != "NOT OBSERVABLE" for result in rule_results
        ),
        "not_observable": sum(
            result["status"] == "NOT OBSERVABLE" for result in rule_results
        ),
        "pass": sum(result["status"] == "PASS" for result in rule_results),
        "fail": sum(result["status"] == "FAIL" for result in rule_results),
    }
    return {
        "security_score": security_score,
        "risk_score": security_score,
        "grade": grade,
        "findings": findings,
        "threat_matrix": threat_matrix,
        "rule_results": rule_results,
        "coverage": coverage,
    }
