"""Render the combined executive and technical HTML report."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "report"


def generate_report(
    label: str,
    ike_facts: dict[str, Any],
    classifier_result: dict[str, Any],
    score_result: dict[str, Any],
    output_dir: str = "./reports/",
) -> str:
    """Write an HTML report and return its absolute path."""
    output_path = Path(output_dir)
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    output_path.mkdir(parents=True, exist_ok=True)

    score = score_result["risk_score"]
    score_color = "red" if score < 40 else "yellow" if score <= 70 else "green"
    encryption = ike_facts.get("encryption_algorithm") or "an unknown encryption algorithm"
    dh_group = ike_facts.get("dh_group") or "an unknown key-exchange group"
    findings = score_result.get("findings", [])
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
        f"The resulting prototype security score is {score}/100.",
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
    )
    path = output_path / f"report_{Path(label).stem}.html"
    path.write_text(html, encoding="utf-8")
    return str(path)
