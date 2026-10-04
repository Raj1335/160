"""Extract leakage-resistant, time-windowed ESP flow features."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pandas as pd
from scapy.all import PcapReader

from features.esp_features import (
    _esp_packet,
    _sha256,
    _traffic_type,
)
from ipsec_parser.ike_parser import parse_ike

WINDOW_FEATURE_COLUMNS = [
    "label",
    "spi",
    "packet_count",
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_size_min",
    "pkt_size_max",
    "iat_mean",
    "iat_std",
    "flow_duration_seconds",
    "packets_per_second",
    "bytes_total",
    "direction",
    "window_index",
    "capture_id",
    "capture_file",
    "capture_sha256",
    "capture_source",
    "profile",
    "is_real_capture",
]


def _empty_window(index: int, timestamp: float) -> dict[str, Any]:
    return {
        "index": index,
        "count": 0,
        "size_sum": 0,
        "size_squared_sum": 0,
        "size_min": 0,
        "size_max": 0,
        "iat_count": 0,
        "iat_sum": 0.0,
        "iat_squared_sum": 0.0,
        "first_timestamp": timestamp,
        "last_timestamp": timestamp,
        "previous_timestamp": timestamp,
    }


def extract_window_features(
    pcap_path: str,
    label: str,
    *,
    window_seconds: float = 2.0,
    gap_seconds: float = 5.0,
) -> pd.DataFrame:
    """Return one feature row per SPI window, splitting on long gaps."""
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file does not exist: {path}")
    if window_seconds <= 0 or gap_seconds <= 0:
        raise ValueError("Window and gap durations must be positive.")

    windows: dict[int, list[dict[str, Any]]] = {}
    active: dict[int, dict[str, Any]] = {}
    sources: dict[int, str] = {}
    errors = 0
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                try:
                    esp = _esp_packet(packet)
                    if esp is None:
                        continue
                    spi, source, timestamp, size = esp
                    current = active.get(spi)
                    if current is not None and (
                        timestamp - current["previous_timestamp"] > gap_seconds
                        or timestamp - current["first_timestamp"] >= window_seconds
                    ):
                        windows.setdefault(spi, []).append(current)
                        current = None
                    if current is None:
                        current = _empty_window(
                            len(windows.get(spi, [])), timestamp
                        )
                        active[spi] = current
                    if spi not in sources:
                        sources[spi] = source
                    if current["count"]:
                        interval = max(
                            0.0, timestamp - current["previous_timestamp"]
                        )
                        current["iat_count"] += 1
                        current["iat_sum"] += interval
                        current["iat_squared_sum"] += interval * interval
                    current["count"] += 1
                    current["size_sum"] += size
                    current["size_squared_sum"] += size * size
                    current["size_min"] = min(current["size_min"], size) if current["count"] > 1 else size
                    current["size_max"] = max(current["size_max"], size)
                    current["last_timestamp"] = timestamp
                    current["previous_timestamp"] = timestamp
                except (AttributeError, IndexError, OSError, TypeError, ValueError):
                    errors += 1
    except (OSError, EOFError) as exc:
        raise ValueError(f"Unable to read PCAP {path}: {exc}") from exc
    if errors:
        raise ValueError(f"Failed to parse {errors} ESP packet(s) in {path}")
    for spi, window in active.items():
        if window["count"]:
            windows.setdefault(spi, []).append(window)

    capture_hash = _sha256(path)
    initiator_ip = parse_ike(str(path)).get("initiator_ip")
    rows = []
    for spi, flow_windows in sorted(windows.items()):
        for window in flow_windows:
            count = window["count"]
            mean_size = window["size_sum"] / count
            duration = window["last_timestamp"] - window["first_timestamp"]
            mean_iat = (
                window["iat_sum"] / window["iat_count"]
                if window["iat_count"]
                else 0.0
            )
            iat_variance = (
                max(
                    0.0,
                    window["iat_squared_sum"] / window["iat_count"]
                    - mean_iat * mean_iat,
                )
                if window["iat_count"]
                else 0.0
            )
            rows.append(
                {
                    "label": _traffic_type(label),
                    "spi": f"0x{spi:08x}",
                    "packet_count": count,
                    "pkt_size_mean": mean_size,
                    "pkt_size_std": math.sqrt(
                        max(
                            0.0,
                            window["size_squared_sum"] / count
                            - mean_size * mean_size,
                        )
                    ),
                    "pkt_size_min": window["size_min"],
                    "pkt_size_max": window["size_max"],
                    "iat_mean": mean_iat,
                    "iat_std": math.sqrt(iat_variance),
                    "flow_duration_seconds": duration,
                    "packets_per_second": count / duration if duration > 0 else 0.0,
                    "bytes_total": window["size_sum"],
                    "direction": (
                        "outbound"
                        if sources[spi] == (initiator_ip or sources[spi])
                        else "inbound"
                    ),
                    "window_index": window["index"],
                    "capture_id": path.stem,
                    "capture_file": path.name,
                    "capture_sha256": capture_hash,
                    "capture_source": "unverified",
                    "profile": None,
                    "is_real_capture": False,
                }
            )
    return pd.DataFrame(rows, columns=WINDOW_FEATURE_COLUMNS)
