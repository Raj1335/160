import json
from pathlib import Path

from ipsec_parser.ike_parser import parse_ike
from tools.generate_demo_capture import generate_demo_capture


def test_sidecar_keeps_ike_and_esp_algorithms_separate(tmp_path):
    capture = generate_demo_capture(tmp_path / "sidecar_capture.pcap")
    Path(f"{capture}.json").write_text(
        json.dumps(
            {
                "source": "documented profile",
                "esp_encryption": "AES-CBC-256",
                "esp_integrity": "HMAC-SHA2-256-128",
            }
        ),
        encoding="utf-8",
    )

    facts = parse_ike(str(capture))

    assert facts["encryption_algorithm"] == "AES-GCM-256"
    assert facts["esp_encryption_algorithm"] == "AES-CBC-256"
    assert facts["fact_sources"]["esp_encryption_algorithm"] == (
        "sidecar: documented profile"
    )


def test_invalid_sidecar_values_warn_and_do_not_replace_capture_values(tmp_path):
    capture = generate_demo_capture(tmp_path / "invalid_values.pcap")
    Path(f"{capture}.json").write_text(
        json.dumps(
            {
                "source": "test metadata",
                "esp_encryption": ["AES-CBC-256"],
                "pfs": "false",
                "ike_version": "IKEv1",
            }
        ),
        encoding="utf-8",
    )

    facts = parse_ike(str(capture))

    assert facts["ike_version"] == "IKEv2"
    assert facts["esp_encryption_algorithm"] is None
    assert facts["pfs_enabled"] is None
    assert len([warning for warning in facts["parse_warnings"] if "ignored" in warning]) == 3


def test_sidecar_without_source_is_ignored(tmp_path):
    capture = generate_demo_capture(tmp_path / "missing_source.pcap")
    Path(f"{capture}.json").write_text(
        json.dumps({"pfs": False}), encoding="utf-8"
    )

    facts = parse_ike(str(capture))

    assert facts["pfs_enabled"] is None
    assert any("non-empty source is required" in warning for warning in facts["parse_warnings"])
