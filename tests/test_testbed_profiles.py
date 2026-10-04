import pytest

from tools.collect_real_dataset import PROFILES_DIR, _load_profile


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
        assert (PROFILES_DIR / profile / "west.conf").is_file()
        assert (PROFILES_DIR / profile / "east.conf").is_file()


def test_profile_loader_rejects_unknown_and_path_like_names():
    with pytest.raises(ValueError, match="Unknown profile"):
        _load_profile("not-a-profile")
    with pytest.raises(ValueError, match="Invalid profile name"):
        _load_profile("..")
