"""Honest cross-validated traffic classifier with a safe untrained path."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import (
    StratifiedGroupKFold,
    cross_val_predict,
    cross_val_score,
)


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "ml" / "model.pkl"
NON_FEATURE_COLUMNS = {
    "label",
    "spi",
    "direction",
    "traffic_type",
    "capture_id",
    "capture_file",
    "capture_sha256",
    "capture_source",
    "is_real_capture",
}


def _insufficient_result(n_samples: int, n_classes: int) -> dict[str, Any]:
    return {
        "status": "insufficient_data",
        "n_samples": n_samples,
        "n_classes": n_classes,
        "cv_accuracy_mean": None,
        "cv_accuracy_std": None,
        "baseline_majority_accuracy": None,
        "feature_importances": None,
        "confusion_matrix": None,
        "note": (
            f"Only {n_samples} labeled flows available across {n_classes} traffic-type "
            "classes — too few for a statistically meaningful train/test split. "
            "Treat classifier output as not yet validated; collect more captures "
            "with varied traffic types. Synthetic demo captures do not validate "
            "real-world classification performance."
        ),
    }


def _remove_unvalidated_model() -> None:
    if MODEL_PATH.is_file():
        MODEL_PATH.unlink()


def _unverified_result(n_samples: int) -> dict[str, Any]:
    _remove_unvalidated_model()
    result = _insufficient_result(0, 0)
    result["note"] = (
        f"Rejected {n_samples} row(s): training requires SHA-256-verified capture "
        "provenance from the real-capture manifest. Filename labels, uploaded "
        "captures, synthetic captures, and CSVs without provenance are not "
        "accepted as training data."
    )
    return result


def train_and_evaluate(csv_path: str = "./data/flow_features.csv") -> dict[str, Any]:
    """Train only on eligible captures; keep capture groups together in CV."""
    path = Path(csv_path)
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        _remove_unvalidated_model()
        return _insufficient_result(0, 0)

    frame = pd.read_csv(path)
    if frame.empty:
        _remove_unvalidated_model()
        return _insufficient_result(0, 0)
    label_column = "traffic_type" if "traffic_type" in frame.columns else "label"
    if label_column not in frame.columns:
        _remove_unvalidated_model()
        return _insufficient_result(0, 0)
    required_provenance = {
        "is_real_capture",
        "capture_id",
        "capture_file",
        "capture_sha256",
        "capture_source",
    }
    if not required_provenance.issubset(frame.columns):
        return _unverified_result(len(frame))
    real_capture = frame["is_real_capture"].map(
        lambda value: value is True
        or str(value).strip().casefold() in {"true", "1"}
    )
    frame = frame[real_capture]
    if frame.empty:
        _remove_unvalidated_model()
        return _insufficient_result(0, 0)
    manifest_path = path.parent / "capture_manifest.jsonl"
    if not manifest_path.is_file():
        return _unverified_result(len(frame))
    manifest: dict[str, dict[str, Any]] = {}
    with manifest_path.open(encoding="utf-8") as manifest_file:
        for line_number, line in enumerate(manifest_file, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid capture manifest JSON on line {line_number}: {exc}"
                ) from exc
            if not isinstance(entry, dict) or not isinstance(
                entry.get("capture_file"), str
            ):
                raise ValueError(
                    f"Invalid capture manifest entry on line {line_number}"
                )
            manifest[entry["capture_file"]] = entry

    valid_digests = frame["capture_sha256"].map(
        lambda value: isinstance(value, str)
        and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None
    )
    valid_capture_ids = frame["capture_id"].map(
        lambda value: isinstance(value, str) and bool(value.strip())
    )
    valid_sources = frame["capture_source"].map(
        lambda value: isinstance(value, str) and bool(value.strip())
    )
    if not (valid_digests & valid_capture_ids & valid_sources).all():
        return _unverified_result(len(frame))
    for row in frame.itertuples(index=False):
        values = row._asdict()
        entry = manifest.get(values["capture_file"])
        if not (
            entry
            and entry.get("is_real_capture") is True
            and entry.get("capture_sha256") == values["capture_sha256"]
            and entry.get("traffic_type") == values[label_column]
            and entry.get("source") == values["capture_source"]
            and Path(values["capture_file"]).stem == values["capture_id"]
        ):
            return _unverified_result(len(frame))
    frame = frame.dropna(subset=[label_column])
    frame = frame[frame[label_column].astype(str).str.strip().ne("")]
    labels = frame[label_column].astype(str)
    n_samples = len(frame)
    n_classes = int(labels.nunique())
    if n_samples < 10 or n_classes < 2:
        _remove_unvalidated_model()
        return _insufficient_result(n_samples, n_classes)

    feature_columns = [
        column
        for column in frame.columns
        if column not in NON_FEATURE_COLUMNS
        and pd.api.types.is_numeric_dtype(frame[column])
    ]
    if not feature_columns:
        _remove_unvalidated_model()
        return {
            **_insufficient_result(n_samples, n_classes),
            "note": "No numeric flow features are available; classifier was not trained.",
        }

    features = frame[feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0)
    groups = frame["capture_sha256"].astype(str)
    labels_per_capture = frame.groupby("capture_sha256")[label_column].nunique()
    hashes_per_capture_id = frame.groupby("capture_id")["capture_sha256"].nunique()
    if labels_per_capture.gt(1).any() or hashes_per_capture_id.gt(1).any():
        return _unverified_result(n_samples)
    groups_per_class = frame.groupby(label_column)["capture_sha256"].nunique()
    min_class_groups = int(groups_per_class.min())
    if min_class_groups < 3:
        _remove_unvalidated_model()
        result = _insufficient_result(n_samples, n_classes)
        result["note"] += (
            f" Capture-aware evaluation requires at least 3 independent captures "
            f"per traffic class; the least represented class has {min_class_groups}."
        )
        return result
    folds = min(5, min_class_groups)
    splitter = StratifiedGroupKFold(
        n_splits=folds, shuffle=True, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    predictions = cross_val_predict(
        model, features, labels, cv=splitter, groups=groups, n_jobs=1
    )
    oof_probabilities = cross_val_predict(
        model,
        features,
        labels,
        cv=splitter,
        groups=groups,
        method="predict_proba",
        n_jobs=1,
    )
    fold_scores = cross_val_score(
        model, features, labels, cv=splitter, groups=groups, n_jobs=1
    )
    baseline = DummyClassifier(strategy="most_frequent")
    baseline_scores = cross_val_score(
        baseline, features, labels, cv=splitter, groups=groups, n_jobs=1
    )
    model.fit(features, labels)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    out_of_fold_by_capture: dict[str, dict[str, Any]] = {}
    capture_hashes: dict[str, str] = {}
    probability_frame = pd.DataFrame(
        oof_probabilities, columns=[str(value) for value in model.classes_]
    )
    probability_frame["capture_id"] = frame["capture_id"].astype(str).to_numpy()
    probability_frame["capture_sha256"] = groups.to_numpy()
    for capture_id, capture_rows in probability_frame.groupby("capture_id"):
        mean_probabilities = capture_rows.drop(
            columns=["capture_id", "capture_sha256"]
        ).mean()
        predicted_label = str(mean_probabilities.idxmax())
        out_of_fold_by_capture[str(capture_id)] = {
            "predicted_label": predicted_label,
            "confidence": float(mean_probabilities[predicted_label]),
        }
        capture_hashes[str(capture_id)] = str(
            capture_rows["capture_sha256"].iloc[0]
        )
    joblib.dump(
        {
            "model": model,
            "feature_columns": feature_columns,
            "out_of_fold_by_capture": out_of_fold_by_capture,
            "capture_hashes": capture_hashes,
        },
        MODEL_PATH,
    )

    matrix = confusion_matrix(labels, predictions, labels=model.classes_).tolist()
    provenance_note = "Training data was assembled from manifest-registered real captures."
    return {
        "status": "trained",
        "n_samples": n_samples,
        "n_classes": n_classes,
        "cv_accuracy_mean": float(fold_scores.mean()),
        "cv_accuracy_std": float(fold_scores.std()),
        "baseline_majority_accuracy": float(baseline_scores.mean()),
        "feature_importances": {
            name: float(value)
            for name, value in zip(feature_columns, model.feature_importances_)
        },
        "confusion_matrix": matrix,
        "note": (
            f"Evaluated with {folds}-fold "
            f"{'capture-grouped ' if groups is not None else ''}"
            f"stratified cross-validation on {n_samples} labeled flows. "
            f"{provenance_note}"
        ),
    }


def predict_traffic_type(flow_features_row: dict[str, Any]) -> dict[str, Any]:
    """Predict one flow, or explicitly report that no validated model exists."""
    if not MODEL_PATH.is_file():
        return {
            "predicted_label": None,
            "confidence": None,
            "note": "Classifier not yet trained — insufficient labeled data.",
        }
    bundle = joblib.load(MODEL_PATH)
    capture_id = flow_features_row.get("capture_id")
    expected_hash = bundle.get("capture_hashes", {}).get(capture_id)
    if capture_id in bundle.get("capture_hashes", {}) and (
        flow_features_row.get("capture_sha256") != expected_hash
    ):
        return {
            "predicted_label": None,
            "confidence": None,
            "note": (
                "Capture identifier is registered with a different SHA-256 digest; "
                "refusing to return an in-sample prediction."
            ),
        }
    if (
        capture_id in bundle.get("out_of_fold_by_capture", {})
        and flow_features_row.get("capture_sha256") == expected_hash
    ):
        return {
            **bundle["out_of_fold_by_capture"][capture_id],
            "note": (
                "Out-of-fold prediction: this complete capture was held out during "
                "training and cross-validation."
            ),
        }
    model = bundle["model"]
    feature_columns = bundle["feature_columns"]
    row = pd.DataFrame(
        [{column: flow_features_row.get(column, 0) for column in feature_columns}]
    )
    row = row.replace([np.inf, -np.inf], np.nan).fillna(0)
    probabilities = model.predict_proba(row)[0]
    best_index = int(np.argmax(probabilities))
    return {
        "predicted_label": str(model.classes_[best_index]),
        "confidence": float(probabilities[best_index]),
        "note": "Prediction from the locally trained Random Forest classifier.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train/evaluate from flow_features.csv")
    parser.add_argument("--csv", type=Path, default=ROOT / "data" / "flow_features.csv")
    args = parser.parse_args()
    result = train_and_evaluate(str(args.csv))
    report_path = ROOT / "ml" / "eval_report.json"
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(pd.Series(result).to_json(indent=2))


if __name__ == "__main__":
    main()
