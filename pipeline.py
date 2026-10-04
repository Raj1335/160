"""Orchestrate one capture through parsing, features, scoring, and reporting."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from features.window_features import extract_window_features
from ipsec_parser.ike_parser import parse_ike
from ml.train_classifier import (
    MODEL_PATH,
    load_evaluation_report,
    predict_traffic_type,
)
from report.generate_report import generate_report
from scoring.scorer import score_capture

ROOT = Path(__file__).resolve().parent
LOGGER = logging.getLogger(__name__)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as capture_file:
        for chunk in iter(lambda: capture_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json_write(path: Path, value: Any) -> None:
    temporary_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary_path.write_text(json.dumps(value, indent=2), encoding="utf-8")
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def analyze(pcap_path: str) -> dict[str, Any]:
    """Analyze a PCAP end to end and return all dashboard/report results."""
    capture = Path(pcap_path)
    if not capture.is_file():
        raise FileNotFoundError(f"PCAP file does not exist: {capture}")
    label = capture.stem
    capture_digest = _file_sha256(capture)
    run_id = f"{capture_digest[:8]}-{uuid.uuid4().hex[:8]}"
    ike_facts = parse_ike(str(capture))
    flow_features = extract_window_features(str(capture), capture.name)

    facts_dir = ROOT / "data" / "ike_facts"
    facts_dir.mkdir(parents=True, exist_ok=True)
    _atomic_json_write(
        facts_dir / f"ike_facts_{capture.stem}-{run_id}.json", ike_facts
    )

    training = load_evaluation_report()
    if training["status"] == "trained" and MODEL_PATH.is_file() and not flow_features.empty:
        flow_predictions = [
            predict_traffic_type(row.to_dict())
            for _, row in flow_features.iterrows()
        ]
        predicted = max(
            flow_predictions,
            key=lambda item: item["confidence"] if item["confidence"] is not None else -1,
        )
        classifier_result = {**predicted, "training": training}
    else:
        classifier_result = {
            "predicted_label": None,
            "confidence": None,
            "note": training["note"],
            "training": training,
        }

    score_result = score_capture(ike_facts)
    findings_dir = ROOT / "data" / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    findings_path = findings_dir / f"findings_{capture.stem}-{run_id}.json"
    _atomic_json_write(findings_path, score_result)
    report_path = generate_report(
        label,
        ike_facts,
        classifier_result,
        score_result,
        output_dir=str(ROOT / "reports"),
        run_id=run_id,
    )
    pdf_path = None
    pdf_export_error = None
    if os.getenv("IPSEC_ANALYZER_PDF", "1").strip().casefold() not in {
        "0",
        "false",
        "no",
        "off",
    }:
        try:
            from report.export_pdf import export_pdf

            pdf_path = export_pdf(report_path)
        except Exception as exc:
            pdf_export_error = str(exc)
            LOGGER.warning("PDF report export failed for %s: %s", report_path, exc)
    return {
        "label": label,
        "ike_facts": ike_facts,
        "flow_features": flow_features.to_dict(orient="records"),
        "classifier_result": classifier_result,
        "classifier_training": training,
        "score_result": score_result,
        "findings_path": str(findings_path),
        "report_path": report_path,
        "pdf_path": pdf_path,
        "pdf_export_error": pdf_export_error,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description="Run the IPsec analyzer on a PCAP.")
    cli.add_argument("pcap", type=Path, help="Path to an input PCAP file")
    cli.add_argument(
        "--fail-under",
        type=int,
        default=0,
        metavar="SCORE",
        help="Exit with status 1 if the security score is below SCORE (0-100).",
    )
    args = cli.parse_args()
    if not 0 <= args.fail_under <= 100:
        cli.error("--fail-under must be between 0 and 100.")
    result = analyze(str(args.pcap))
    printable = {key: value for key, value in result.items() if key != "flow_features"}
    print(json.dumps(printable, indent=2, default=str))
    return int(result["score_result"]["security_score"] < args.fail_under)


if __name__ == "__main__":
    raise SystemExit(main())
