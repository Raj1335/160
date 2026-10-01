"""Orchestrate one capture through parsing, features, scoring, and reporting."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from features.esp_features import build_feature_dataset, extract_flow_features
from ml.train_classifier import predict_traffic_type, train_and_evaluate
from parser.ike_parser import parse_ike
from report.generate_report import generate_report
from scoring.scorer import score_capture


ROOT = Path(__file__).resolve().parent


def analyze(pcap_path: str) -> dict[str, Any]:
    """Analyze a PCAP end to end and return all dashboard/report results."""
    capture = Path(pcap_path)
    if not capture.is_file():
        raise FileNotFoundError(f"PCAP file does not exist: {capture}")
    label = capture.stem
    ike_facts = parse_ike(str(capture))
    flow_features = extract_flow_features(str(capture), capture.name)

    facts_dir = ROOT / "data" / "ike_facts"
    facts_dir.mkdir(parents=True, exist_ok=True)
    (facts_dir / f"ike_facts_{capture.stem}.json").write_text(
        json.dumps(ike_facts, indent=2), encoding="utf-8"
    )

    dataset_path = ROOT / "data" / "flow_features.csv"
    build_feature_dataset(ROOT / "captures", dataset_path)
    training = train_and_evaluate(str(dataset_path))
    (ROOT / "ml").mkdir(parents=True, exist_ok=True)
    (ROOT / "ml" / "eval_report.json").write_text(
        json.dumps(training, indent=2), encoding="utf-8"
    )
    if training["status"] == "trained" and not flow_features.empty:
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
    findings_path = findings_dir / f"findings_{capture.stem}.json"
    findings_path.write_text(json.dumps(score_result, indent=2), encoding="utf-8")
    report_path = generate_report(
        label,
        ike_facts,
        classifier_result,
        score_result,
        output_dir=str(ROOT / "reports"),
    )
    return {
        "label": label,
        "ike_facts": ike_facts,
        "flow_features": flow_features.to_dict(orient="records"),
        "classifier_result": classifier_result,
        "classifier_training": training,
        "score_result": score_result,
        "findings_path": str(findings_path),
        "report_path": report_path,
    }


def main() -> None:
    cli = argparse.ArgumentParser(description="Run the IPsec analyzer on a PCAP.")
    cli.add_argument("pcap", type=Path, help="Path to an input PCAP file")
    args = cli.parse_args()
    result = analyze(str(args.pcap))
    printable = {key: value for key, value in result.items() if key != "flow_features"}
    print(json.dumps(printable, indent=2, default=str))


if __name__ == "__main__":
    main()
