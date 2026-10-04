import json

import pytest

from scoring.scorer import score_capture
from tools.collect_real_dataset import (
    PROFILES_DIR,
    _load_profile,
    _write_capture_sidecar,
)


def test_all_profiles_have_complete_metadata_and_endpoint_configs():
    expected = {
        "strong-gcm-tunnel-ikev2",
        "medium-cbc-tunnel-ikev2",
        "weak-3des-tunnel-ikev2",
        "ikev1-main-aes",
        "ikev1-aggressive-weak",
        "pfs-off-tunnel-ikev2",
    }
    assert {path.name for path in PROFILES_DIR.iterdir() if path.is_dir()} == expected

    for profile in sorted(expected):
        metadata = _load_profile(profile)
        assert metadata["name"] == profile
        assert metadata["ike_version"] in {"IKEv1", "IKEv2"}
        assert metadata["mode"] == "tunnel"
        assert isinstance(metadata["pfs"], bool)
        assert isinstance(metadata["expected_findings"], list)
        if metadata["ike_version"] == "IKEv1":
            assert metadata["ike_exchange_mode"] in {"Main Mode", "Aggressive Mode"}
        assert (PROFILES_DIR / profile / "west.conf").is_file()
        assert (PROFILES_DIR / profile / "east.conf").is_file()
        facts = {
            "ike_version": metadata["ike_version"],
            "ike_exchange_mode": metadata.get("ike_exchange_mode"),
            "pfs_enabled": metadata["pfs"],
            "esp_encryption_algorithm": metadata["esp_encryption"],
            "esp_integrity_algorithm": metadata["esp_integrity"],
            "dh_group": metadata["dh_group"],
            "sa_lifetime_seconds": metadata["sa_lifetime_seconds"],
            "fact_sources": {
                key: f"sidecar: profile {profile}"
                for key in (
                    "ike_version",
                    "ike_exchange_mode",
                    "pfs_enabled",
                    "esp_encryption_algorithm",
                    "esp_integrity_algorithm",
                    "dh_group",
                    "sa_lifetime_seconds",
                )
            },
        }
        scored = score_capture(facts)
        assert scored["grade"] == metadata["expected_grade"]
        assert set(metadata["expected_findings"]).issubset(
            {finding["id"] for finding in scored["findings"]}
        )


def test_profile_loader_rejects_unknown_and_path_like_names():
    with pytest.raises(ValueError, match="Unknown profile"):
        _load_profile("not-a-profile")
    with pytest.raises(ValueError, match="Invalid profile name"):
        _load_profile("..")


def test_collector_writes_sidecar_with_configured_profile_provenance(tmp_path):
    profile = "weak-3des-tunnel-ikev2"
    metadata = _load_profile(profile)
    capture = tmp_path / "capture.pcap"

    _write_capture_sidecar(capture, profile, metadata)

    sidecar = json.loads(
        capture.with_suffix(".pcap.json").read_text(encoding="utf-8")
    )
    assert sidecar["source"] == f"strongSwan testbed profile {profile}"
    assert sidecar["esp_encryption"] == "3DES"
    assert sidecar["esp_integrity"] == "HMAC-SHA1-96"
    assert sidecar["pfs"] is True
