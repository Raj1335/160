"""Render the combined executive and technical HTML report."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "report"


def remediation_config(findings: list[dict[str, Any]]) -> dict[str, str] | None:
    """Return a conservative strongSwan proposal when weak crypto was observed."""
    weak_ids = {
        "encryption_des",
        "weak_encryption",
        "weak_integrity",
        "weak_dh_group",
        "short_key_aes",
        "ikev1_deprecated",
        "ikev1_aggressive_mode",
    }
    if not any(finding.get("id") in weak_ids for finding in findings):
        return None
    strongswan = (
        "conn analyzer-remediation\n"
        "    keyexchange=ikev2\n"
        "    type=tunnel\n"
        "    authby=psk\n"
        "    ike=aes256gcm16-prfsha256-curve25519!\n"
        "    esp=aes256gcm16-curve25519!\n"
        "    auto=add"
    )
    xfrm = (
        "# Review kernel-installed SAs after strongSwan negotiates the new policy:\n"
        "ip xfrm state list\n"
        "ip xfrm policy list"
    )
    return {"strongswan": strongswan, "xfrm": xfrm}


def generate_report(
    label: str,
    ike_facts: dict[str, Any],
    classifier_result: dict[str, Any],
    score_result: dict[str, Any],
    output_dir: str = "./reports/",
    run_id: str | None = None,
) -> str:
    """Write an HTML report and return its absolute path."""
    output_path = Path(output_dir)
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    output_path.mkdir(parents=True, exist_ok=True)

    score = score_result.get("security_score", score_result.get("risk_score", 100))
    grade = score_result.get("grade", "F")
    score_color = "red" if score < 40 else "yellow" if score <= 70 else "green"
    encryption = ike_facts.get("encryption_algorithm") or "an unknown encryption algorithm"
    dh_group = ike_facts.get("dh_group") or "an unknown key-exchange group"
    findings = score_result.get("findings", [])
    coverage = score_result.get("coverage", {})
    remediation = remediation_config(findings)
    critical = next(
        (finding["message"] for finding in findings if finding["severity"] == "critical"),
        None,
    )
    concerns = (
        f"{len(findings)} configured security concern(s) were identified"
        if findings
        else "No configured security rules were triggered by observed values"
    )
    summary = [
        f"This capture reports {encryption} and {dh_group}; unavailable facts remain unknown rather than inferred.",
        f"{concerns}{f', including {critical}' if critical else ''}.",
        f"The resulting prototype security score is {score}/100 (grade {grade}).",
        (
            f"Coverage: {coverage['observed']} of {coverage['total']} rules "
            "had observable inputs."
            if coverage
            else "Rule input coverage is not available."
        ),
        "Encrypted IKE payloads were not decrypted; review the technical details and capture limitations before drawing conclusions.",
    ]
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(("html", "xml")),
    )
    template = environment.get_template("template_combined.html")
    classifier_training = classifier_result.get("training", classifier_result)
    prediction = {
        "predicted_label": classifier_result.get("predicted_label"),
        "confidence": classifier_result.get("confidence"),
        "note": classifier_result.get("note", "No classifier prediction is available."),
    }
    html = template.render(
        label=label,
        analyzed_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        score_color=score_color,
        score_result=score_result,
        ike_facts=ike_facts,
        classifier_result=prediction,
        classifier_training=classifier_training,
        executive_summary=summary,
        top_findings=findings[:3],
        remediation=remediation,
    )
    report_id = run_id or hashlib.sha256(label.encode("utf-8")).hexdigest()[:8]
    path = output_path / f"report_{Path(label).stem}-{report_id}.html"
    temporary_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary_path.write_text(html, encoding="utf-8")
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return str(path)
