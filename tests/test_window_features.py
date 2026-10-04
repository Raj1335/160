import pytest
from scapy.all import IP, Ether, Raw, wrpcap

from features.window_features import (
    WINDOW_FEATURE_COLUMNS,
    extract_window_features,
)
from ml.train_classifier import NON_FEATURE_COLUMNS


def _esp_packet(spi, sequence, timestamp, size=48):
    packet = (
        Ether()
        / IP(src="192.0.2.1", dst="198.51.100.1", proto=50)
        / Raw(load=spi.to_bytes(4, "big") + sequence.to_bytes(4, "big") + b"x" * size)
    )
    packet.time = timestamp
    return packet


def test_long_idle_gap_forces_a_new_feature_window(tmp_path):
    capture = tmp_path / "tunnel_aes256cbc_pfs-on_ipv4_web-run01.pcap"
    wrpcap(
        str(capture),
        [
            _esp_packet(0x01020304, 1, 100.0),
            _esp_packet(0x01020304, 2, 100.2),
            _esp_packet(0x01020304, 3, 110.0),
            _esp_packet(0x01020304, 4, 110.2),
        ],
    )

    features = extract_window_features(
        str(capture), capture.name, window_seconds=60, gap_seconds=2
    )

    assert len(features) == 2
    assert features["window_index"].tolist() == [0, 1]
    assert features["packet_count"].tolist() == [2, 2]
    assert set(features["label"]) == {"web"}


def test_window_feature_columns_are_stable_and_metadata_is_not_a_model_feature(
    tmp_path,
):
    capture = tmp_path / "empty.pcap"
    wrpcap(str(capture), [])

    features = extract_window_features(str(capture), capture.name)

    assert list(features.columns) == WINDOW_FEATURE_COLUMNS
    assert features.empty
    assert {"window_index", "capture_id", "capture_sha256", "label"} <= (
        NON_FEATURE_COLUMNS
    )


def test_invalid_window_sizes_are_rejected(tmp_path):
    capture = tmp_path / "empty.pcap"
    wrpcap(str(capture), [])

    with pytest.raises(ValueError, match="must be positive"):
        extract_window_features(str(capture), capture.name, window_seconds=0)
