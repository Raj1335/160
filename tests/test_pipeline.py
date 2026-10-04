from __future__ import annotations

import struct
import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from features.esp_features import (
    FEATURE_COLUMNS,
    build_feature_dataset,
    extract_flow_features,
)
from ml.train_classifier import predict_traffic_type, train_and_evaluate
import ml.train_classifier as classifier
import pipeline
from parser.ike_parser import parse_ike
from scoring.scorer import score_capture
from tools.generate_demo_capture import generate_demo_capture
from tools.register_capture import register_capture
from scapy.all import Ether, IP, UDP, wrpcap


def test_pipeline_on_synthetic_pcap(tmp_path, monkeypatch):
    capture = generate_demo_capture(tmp_path / "demo_aesgcm256_pfs-on_ipv4_icmp.pcap")
    (tmp_path / "captures").mkdir()
    monkeypatch.setattr(pipeline, "ROOT", tmp_path)

    facts = parse_ike(str(capture))
    assert facts["ike_version"] == "IKEv2"
    assert facts["encryption_algorithm"] == "AES-GCM-256"
    assert facts["integrity_algorithm"] == "N/A (combined with AEAD)"
    assert facts["pfs_enabled"] is None
    assert facts["ike_sa_established"] is True

    flows = extract_flow_features(str(capture), capture.name)
    assert len(flows) == 2
    assert set(flows["label"]) == {"icmp"}
    assert flows["packet_count"].tolist() == [4, 4]

    training_csv = tmp_path / "flow_features.csv"
    flows.to_csv(training_csv, index=False)
    training = train_and_evaluate(str(training_csv))
    assert training["status"] == "insufficient_data"
    assert training["cv_accuracy_mean"] is None
    assert "not yet validated" in training["note"]

    score = score_capture(facts)
    assert score["security_score"] == 100
    assert not any(finding["id"] == "long_sa_lifetime" for finding in score["findings"])

    result = pipeline.analyze(str(capture))
    assert {
        "label",
        "ike_facts",
        "flow_features",
        "classifier_result",
        "classifier_training",
        "score_result",
        "report_path",
    } <= result.keys()
    assert result["ike_facts"]["ike_sa_established"] is True
    assert result["classifier_training"]["status"] == "insufficient_data"
    assert pd.read_csv(tmp_path / "data" / "flow_features.csv").empty
    assert (tmp_path / "data" / "ike_facts" / f"ike_facts_{capture.stem}.json").is_file()
    assert (tmp_path / "data" / "findings" / f"findings_{capture.stem}.json").is_file()
    report_html = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "Classifier not yet validated" in report_html
    assert "Grade: <strong>A</strong>" in report_html
    assert "Scoring Coverage" in report_html


def test_scorer_applies_hard_cap_for_weak_encryption():
    result = score_capture(
        {
            "encryption_algorithm": "DES",
            "integrity_algorithm": "HMAC-SHA2-256",
            "dh_group": "MODP2048",
            "pfs_enabled": True,
            "ike_sa_established": True,
            "sa_lifetime_seconds": 3600,
        }
    )
    assert result["security_score"] == 20
    assert result["grade"] == "F"
    assert any(finding["id"] == "encryption_des" for finding in result["findings"])


def test_unknown_sa_lifetime_is_not_scored_as_a_finding():
    result = score_capture({"sa_lifetime_seconds": None})

    assert result["security_score"] == 100
    assert not any(finding["id"] == "long_sa_lifetime" for finding in result["findings"])


def test_scorer_coverage_counts_observed_and_unknown_rules_without_penalty():
    result = score_capture(
        {
            "encryption_algorithm": "AES-GCM-256",
            "integrity_algorithm": "N/A (combined with AEAD)",
            "dh_group": None,
            "pfs_enabled": None,
            "ike_sa_established": True,
            "sa_lifetime_seconds": None,
        }
    )

    coverage = result["coverage"]
    assert coverage["total"] == 9
    assert coverage["observed"] + coverage["not_observable"] == coverage["total"]
    assert coverage["pass"] + coverage["fail"] == coverage["observed"]
    assert coverage["not_observable"] > 0
    assert result["security_score"] == 100
    assert all(
        rule["status"] == "NOT OBSERVABLE"
        for rule in result["rule_results"]
        if rule["observed_value"] is None
    )


def test_observed_sa_lifetime_over_24_hours_is_scored():
    result = score_capture({"sa_lifetime_seconds": 86401})

    assert result["security_score"] == 95
    assert any(finding["id"] == "long_sa_lifetime" for finding in result["findings"])


def test_classifier_handles_missing_training_csv(tmp_path):
    result = train_and_evaluate(str(tmp_path / "missing.csv"))
    assert result["status"] == "insufficient_data"
    assert result["n_samples"] == 0


def test_classifier_rejects_unverified_training_csv(tmp_path, monkeypatch):
    training_csv = tmp_path / "unverified-training.csv"
    rows = [
        {
            "label": label,
            "spi": f"0x{index:08x}",
            "packet_count": index + 1 if label == "bulk" else 2,
            "pkt_size_mean": 1200 if label == "bulk" else 100,
            "pkt_size_std": index,
            "direction": "outbound",
        }
        for label in ("bulk", "icmp")
        for index in range(5)
    ]
    pd.DataFrame(rows).to_csv(training_csv, index=False)
    monkeypatch.setattr(classifier, "MODEL_PATH", tmp_path / "model.pkl")

    result = train_and_evaluate(str(training_csv))
    assert result["status"] == "insufficient_data"
    assert result["n_samples"] == 0
    assert "Rejected 10 row(s)" in result["note"]
    assert not (tmp_path / "model.pkl").exists()


def test_feature_extractor_returns_stable_empty_frame(tmp_path):
    capture = tmp_path / "no_esp.pcap"
    wrpcap(str(capture), [Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP()])
    frame = extract_flow_features(str(capture), capture.name)
    assert list(frame.columns) == FEATURE_COLUMNS
    assert frame.empty


def test_training_dataset_requires_hash_verified_real_capture_manifest(tmp_path):
    captures = tmp_path / "captures"
    captures.mkdir()
    capture = generate_demo_capture(
        captures / "tunnel_aesgcm256_pfs-on_ipv4_icmp-run01.pcap"
    )
    digest = hashlib.sha256(capture.read_bytes()).hexdigest()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    manifest = data_dir / "capture_manifest.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "capture_file": capture.name,
                "capture_sha256": digest,
                "source": "strongswan-docker-testbed",
                "is_real_capture": True,
                "traffic_type": "icmp",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    dataset = build_feature_dataset(captures, data_dir / "flow_features.csv")

    assert len(dataset) == 2
    assert set(dataset["label"]) == {"icmp"}
    assert set(dataset["capture_source"]) == {"strongswan-docker-testbed"}
    assert dataset["is_real_capture"].all()

    capture.write_bytes(capture.read_bytes() + b"tampered")
    changed_dataset = build_feature_dataset(captures, data_dir / "flow_features.csv")
    assert not changed_dataset["is_real_capture"].any()
    assert set(changed_dataset["capture_source"]) == {"unverified"}


def test_fixture_manifest_sha256_sidecar_and_expected_grade():
    fixture_dir = Path(__file__).resolve().parents[1] / "captures" / "fixtures"
    manifest_path = fixture_dir / "capture_manifest.jsonl"
    entries = [
        json.loads(line)
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(entries) == 3
    for entry in entries:
        capture = fixture_dir / entry["capture_file"]
        digest = hashlib.sha256(capture.read_bytes()).hexdigest()
        facts = parse_ike(str(capture))
        scored = score_capture(facts)

        assert entry["is_real_capture"] is True
        assert digest == entry["capture_sha256"]
        assert entry["source_capture_sha256"]
        assert entry["fixture_packet_count"] > 0
        assert facts["fact_sources"]["encryption_algorithm"].startswith("sidecar:")
        assert scored["grade"] == entry["expected_grade"]


def test_pipeline_report_labels_sidecar_fact_source(tmp_path, monkeypatch):
    capture = generate_demo_capture(tmp_path / "sidecar_report.pcap")
    Path(f"{capture}.json").write_text(
        json.dumps(
            {
                "source": "documented testbed profile",
                "mode": "tunnel",
                "pfs": True,
                "esp_encryption": "AES-CBC-256",
                "esp_integrity": "HMAC-SHA2-256-128",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "captures").mkdir()
    monkeypatch.setattr(pipeline, "ROOT", tmp_path)

    result = pipeline.analyze(str(capture))

    report_html = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "sidecar: documented testbed profile" in report_html
    assert result["score_result"]["grade"] == "A"


def test_classifier_excludes_unverified_captures(tmp_path, monkeypatch):
    training_csv = tmp_path / "unverified.csv"
    rows = []
    for label in ("bulk", "icmp"):
        for index in range(5):
            capture_id = f"{label}-{index}"
            rows.append(
                {
                    "label": label,
                    "packet_count": index,
                    "pkt_size_mean": index * 10,
                    "capture_id": capture_id,
                    "capture_file": f"{capture_id}.pcap",
                    "capture_sha256": hashlib.sha256(capture_id.encode()).hexdigest(),
                    "capture_source": "claimed real but unregistered",
                    "is_real_capture": True,
                }
            )
    pd.DataFrame(rows).to_csv(training_csv, index=False)
    monkeypatch.setattr(classifier, "MODEL_PATH", tmp_path / "model.pkl")

    result = train_and_evaluate(str(training_csv))

    assert result["status"] == "insufficient_data"
    assert result["n_samples"] == 0
    assert not (tmp_path / "model.pkl").exists()


def test_external_capture_registration_requires_explicit_real_attestation(
    tmp_path, monkeypatch
):
    capture = generate_demo_capture(tmp_path / "sample.pcap")
    monkeypatch.setattr(
        "tools.register_capture.CAPTURES_DIR", tmp_path / "registered-captures"
    )
    monkeypatch.setattr(
        "tools.register_capture.MANIFEST_PATH", tmp_path / "manifest.jsonl"
    )

    with pytest.raises(ValueError, match="explicit real-capture attestation"):
        register_capture(
            capture,
            "icmp",
            "test source",
            "test license",
            attest_real_capture=False,
        )

    assert not (tmp_path / "registered-captures").exists()
    assert not (tmp_path / "manifest.jsonl").exists()


def test_capture_grouped_classifier_predicts_held_out_captures(tmp_path, monkeypatch):
    training_csv = tmp_path / "grouped.csv"
    rows = []
    for label, size in (("icmp", 90), ("web", 400), ("bulk", 1400)):
        for capture_number in range(3):
            capture_id = f"{label}-run{capture_number}"
            for direction in ("inbound", "outbound"):
                rows.append(
                    {
                        "label": label,
                        "packet_count": 20 + capture_number,
                        "pkt_size_mean": size + capture_number,
                        "direction": direction,
                        "capture_id": capture_id,
                        "capture_file": f"{capture_id}.pcap",
                        "capture_sha256": hashlib.sha256(
                            f"{label}-{capture_number}".encode()
                        ).hexdigest(),
                        "capture_source": "strongswan-docker-testbed",
                        "is_real_capture": True,
                    }
                )
    pd.DataFrame(rows).to_csv(training_csv, index=False)
    manifest = [
        {
            "capture_file": f"{label}-run{capture_number}.pcap",
            "capture_sha256": hashlib.sha256(
                f"{label}-{capture_number}".encode()
            ).hexdigest(),
            "source": "strongswan-docker-testbed",
            "is_real_capture": True,
            "traffic_type": label,
        }
        for label in ("icmp", "web", "bulk")
        for capture_number in range(3)
    ]
    (tmp_path / "capture_manifest.jsonl").write_text(
        "".join(json.dumps(entry) + "\n" for entry in manifest),
        encoding="utf-8",
    )
    monkeypatch.setattr(classifier, "MODEL_PATH", tmp_path / "model.pkl")

    result = train_and_evaluate(str(training_csv))
    prediction = predict_traffic_type(rows[0])

    assert result["status"] == "trained"
    assert "capture-grouped" in result["note"]
    assert prediction["predicted_label"] in {"bulk", "icmp", "web"}
    assert 0 <= prediction["confidence"] <= 1
    assert "held out" in prediction["note"]


def test_nat_traversal_ike_is_not_mistaken_for_esp(tmp_path):
    header = struct.pack(
        "!8s8sBBBBII",
        b"initiatr",
        b"responder",
        0,
        0x20,
        34,
        0x08,
        0,
        28,
    )
    packet = (
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=4500, dport=4500)
        / b"\x00\x00\x00\x00"
        / header
    )
    capture = tmp_path / "natt_ike.pcap"
    wrpcap(str(capture), [packet])

    facts = parse_ike(str(capture))
    features = extract_flow_features(str(capture), capture.name)
    assert facts["ike_version"] == "IKEv2"
    assert features.empty


def test_incomplete_ike_auth_exchange_remains_unknown(tmp_path):
    spi_i = b"initiatr"
    spi_r = b"responder"
    encrypted_body = b"\x00" * 16
    encrypted_payload = struct.pack("!BBH", 0, 0, 4 + len(encrypted_body)) + encrypted_body
    ike_auth = struct.pack(
        "!8s8sBBBBII",
        spi_i,
        spi_r,
        46,
        0x20,
        35,
        0x08,
        1,
        28 + len(encrypted_payload),
    ) + encrypted_payload
    capture = tmp_path / "incomplete_ike_auth.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=500, dport=500)
            / ike_auth
        ],
    )

    facts = parse_ike(str(capture))

    assert facts["ike_sa_established"] is None
    assert facts["ike_failure_notifications"] == []


def test_cleartext_ike_init_failure_notify_marks_sa_failed(tmp_path):
    spi_i = b"initiatr"
    spi_r = b"\x00" * 8
    notify_body = struct.pack("!BBH", 0, 0, 14)
    notify_payload = struct.pack("!BBH", 0, 0, 4 + len(notify_body)) + notify_body
    ike_init_response = struct.pack(
        "!8s8sBBBBII",
        spi_i,
        spi_r,
        41,
        0x20,
        34,
        0x20,
        0,
        28 + len(notify_payload),
    ) + notify_payload
    capture = tmp_path / "ike_init_no_proposal.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="192.0.2.2", dst="192.0.2.1")
            / UDP(sport=500, dport=500)
            / ike_init_response
        ],
    )

    facts = parse_ike(str(capture))

    assert facts["ike_sa_established"] is False
    assert facts["ike_failure_notifications"] == [
        {"type": 14, "name": "NO_PROPOSAL_CHOSEN", "packet": 1}
    ]


def test_truncated_ike_packet_does_not_create_false_exchange_facts(tmp_path):
    ike_header = struct.pack(
        "!8s8sBBBBII",
        b"initiatr",
        b"\x00" * 8,
        33,
        0x20,
        34,
        0x08,
        0,
        160,
    )
    capture = tmp_path / "truncated_ike.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=500, dport=500)
            / ike_header
        ],
    )

    facts = parse_ike(str(capture))

    assert facts["ike_exchange_mode"] is None
    assert facts["child_sa_established"] is None


def test_valid_sidecar_applies_values_and_records_explicit_source(tmp_path):
    capture = generate_demo_capture(tmp_path / "sidecar.pcap")
    Path(f"{capture}.json").write_text(
        json.dumps(
            {
                "source": "strongSwan profile strong-gcm-tunnel-ikev2",
                "mode": "tunnel",
                "pfs": False,
                "esp_encryption": "AES-GCM-256",
                "esp_integrity": "N/A (combined with AEAD)",
                "sa_lifetime_seconds": 3600,
            }
        ),
        encoding="utf-8",
    )

    facts = parse_ike(str(capture))

    assert facts["mode"] == "tunnel"
    assert facts["pfs_enabled"] is False
    assert facts["encryption_algorithm"] == "AES-GCM-256"
    assert facts["sa_lifetime_seconds"] == 3600
    assert facts["fact_sources"]["pfs_enabled"].startswith("sidecar:")
    scored = score_capture(facts)
    assert any(item["id"] == "pfs_disabled" for item in scored["findings"])


def test_invalid_sidecar_values_are_ignored_with_warning(tmp_path):
    capture = generate_demo_capture(tmp_path / "bad_sidecar.pcap")
    Path(f"{capture}.json").write_text(
        json.dumps(
            {
                "source": "test fixture metadata",
                "mode": "guess",
                "pfs": "false",
                "esp_encryption": ["AES-GCM-256"],
                "unrecognized": "value",
            }
        ),
        encoding="utf-8",
    )

    facts = parse_ike(str(capture))

    assert facts["mode"] is None
    assert facts["pfs_enabled"] is None
    assert facts["encryption_algorithm"] == "AES-GCM-256"
    sidecar_warnings = [
        warning for warning in facts["parse_warnings"] if "Sidecar " in warning
    ]
    assert len(sidecar_warnings) == 4
    assert all("ignored" in warning for warning in sidecar_warnings)


@pytest.mark.parametrize(
    ("exchange", "expected_mode"),
    ((2, "Main Mode"), (4, "Aggressive Mode")),
)
def test_ikev1_exchange_mode_is_observed_and_scored(
    tmp_path, exchange, expected_mode
):
    ike_header = struct.pack(
        "!8s8sBBBBII",
        b"initiatr",
        b"\x00" * 8,
        0,
        0x10,
        exchange,
        0x08,
        0,
        28,
    )
    capture = tmp_path / f"ikev1_exchange_{exchange}.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=500, dport=500)
            / ike_header
        ],
    )

    facts = parse_ike(str(capture))
    result = score_capture(facts)

    assert facts["ike_version"] == "IKEv1"
    assert facts["ike_exchange_mode"] == expected_mode
    assert any(item["id"] == "ikev1_deprecated" for item in result["findings"])
    if exchange == 4:
        assert result["grade"] == "F"
        assert any(item["id"] == "ikev1_aggressive_mode" for item in result["findings"])
    else:
        assert result["grade"] == "D"
