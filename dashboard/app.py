"""Streamlit UI for selecting, analyzing, and downloading capture reports."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from features.esp_features import build_feature_dataset
from ml.train_classifier import train_and_evaluate
from pipeline import ROOT, analyze


CAPTURES_DIR = ROOT / "captures"


def _show_results(result: dict) -> None:
    st.subheader(f"Analysis: {result['label']}")
    score = result["score_result"].get("security_score", result["score_result"].get("risk_score", 100))
    grade = result["score_result"].get("grade", "F")
    st.metric("Security score (higher is better)", f"{score} / 100")
    st.caption(f"Grade: {grade}")
    st.dataframe(result["score_result"]["threat_matrix"], use_container_width=True)
    with st.expander("Raw IKE facts"):
        st.json(result["ike_facts"])
    st.subheader("Traffic classifier")
    training = result["classifier_training"]
    st.info(training["note"])
    prediction = result["classifier_result"]
    st.write(f"Predicted traffic type: {prediction['predicted_label'] or 'Not available'}")
    confidence = prediction["confidence"]
    st.write(
        f"Confidence: {confidence:.1%}"
        if confidence is not None
        else "Confidence: N/A — classifier not yet validated"
    )
    if confidence is not None:
        st.caption(prediction["note"])
    if training["status"] == "trained":
        st.caption(
            f"Evaluation: {training['n_samples']} flows across "
            f"{training['n_classes']} traffic classes; "
            f"cross-validation accuracy {training['cv_accuracy_mean']:.1%} "
            f"(majority baseline {training['baseline_majority_accuracy']:.1%})."
        )
    report_path = Path(result["report_path"])
    st.download_button(
        "Download HTML report",
        data=report_path.read_bytes(),
        file_name=report_path.name,
        mime="text/html",
    )
    if result.get("pdf_path"):
        pdf_path = Path(result["pdf_path"])
        st.download_button(
            "Download PDF report",
            data=pdf_path.read_bytes(),
            file_name=pdf_path.name,
            mime="application/pdf",
        )
    elif result.get("pdf_export_error"):
        st.warning(f"PDF export unavailable: {result['pdf_export_error']}")


def _training_data_status() -> None:
    st.sidebar.subheader("Training data")
    st.sidebar.caption(
        "Automatic training accepts only captures whose SHA-256 matches a local "
        "manifest entry declared real. The digest binds the entry to the file; "
        "the source/label still require trustworthy provenance. Uploads are "
        "analyzed but are not silently treated as training examples."
    )
    if st.sidebar.button("Rebuild dataset and train model"):
        with st.spinner("Rebuilding verified features and evaluating the classifier..."):
            build_feature_dataset(CAPTURES_DIR, ROOT / "data" / "flow_features.csv")
            training = train_and_evaluate(
                str(ROOT / "data" / "flow_features.csv")
            )
            (ROOT / "ml" / "eval_report.json").write_text(
                json.dumps(training, indent=2), encoding="utf-8"
            )
        if training["status"] == "trained":
            st.sidebar.success(
                f"Model evaluated on {training['n_samples']} flows across "
                f"{training['n_classes']} classes."
            )
        else:
            st.sidebar.warning(training["note"])
    features_path = ROOT / "data" / "flow_features.csv"
    if not features_path.is_file():
        st.sidebar.info("Training features have not been built yet.")
        return
    dataset = pd.read_csv(features_path)
    if "is_real_capture" not in dataset:
        st.sidebar.info("No verified real-capture provenance is available yet.")
        return
    real_rows = dataset[dataset["is_real_capture"].fillna(False).astype(bool)]
    st.sidebar.metric("Verified real ESP flows", len(real_rows))
    if not real_rows.empty:
        class_counts = real_rows["label"].value_counts().to_dict()
        st.sidebar.write("Flows by traffic class")
        st.sidebar.json(class_counts)


def main() -> None:
    st.set_page_config(page_title="IPsec Analyzer", page_icon="🔐", layout="wide")
    st.title("IPsec Configuration Analyzer")
    st.caption(
        "Offline capture analysis. Encrypted IKE payloads are not decrypted; "
        "unknown values are not guessed."
    )
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    _training_data_status()
    captures = sorted(CAPTURES_DIR.glob("*.pcap"))
    source = st.radio("Capture source", ("Existing capture", "Upload a PCAP"), horizontal=True)
    selected_path = None
    uploaded_file = None
    if source == "Existing capture":
        if captures:
            selected_path = st.selectbox(
                "Choose a capture", captures, format_func=lambda path: path.name
            )
        else:
            st.info(
                "No captures are present. Upload a real PCAP, or generate a synthetic "
                "development fixture with `python tools/generate_demo_capture.py`."
            )
    else:
        uploaded_file = st.file_uploader("Upload a .pcap file", type=["pcap", "pcapng"])

    should_analyze = selected_path is not None if source == "Existing capture" else uploaded_file is not None
    if should_analyze:
        uploaded_content = None
        if selected_path is not None:
            capture_stat = selected_path.stat()
            cache_key = (
                f"{selected_path.resolve()}:{capture_stat.st_size}:"
                f"{capture_stat.st_mtime_ns}"
            )
        else:
            if uploaded_file is None:
                st.error("Select a capture or upload a PCAP to continue.")
                st.stop()
            uploaded_content = uploaded_file.getvalue()
            content_digest = hashlib.sha256(uploaded_content).hexdigest()
            cache_key = f"upload:{uploaded_file.name}:{content_digest}"
        if st.session_state.get("analysis_key") != cache_key:
            try:
                with st.spinner("Analyzing capture..."):
                    if selected_path is not None:
                        result = analyze(str(selected_path))
                    else:
                        suffix = Path(uploaded_file.name).suffix or ".pcap"
                        safe_name = Path(uploaded_file.name).name
                        if not Path(safe_name).suffix:
                            safe_name = f"{safe_name}{suffix}"
                        with tempfile.TemporaryDirectory(prefix="ipsec-analyzer-") as temp_dir:
                            temporary_capture = Path(temp_dir) / safe_name
                            temporary_capture.write_bytes(uploaded_content)
                            result = analyze(str(temporary_capture))
                st.session_state["analysis_result"] = result
                st.session_state["analysis_key"] = cache_key
            except (OSError, ValueError, KeyError) as exc:
                st.error(f"Capture analysis failed: {exc}")
                st.stop()
        result = st.session_state.get("analysis_result")
        if result:
            _show_results(result)


if __name__ == "__main__":
    main()
