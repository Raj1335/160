"""Extract non-decrypting packet timing and size features per ESP SPI."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
from pathlib import Path
from typing import Any

import pandas as pd
from scapy.all import IP, IPv6, UDP, PcapReader


ROOT = Path(__file__).resolve().parents[1]
FEATURE_COLUMNS = [
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
    "capture_id",
    "capture_file",
    "capture_sha256",
    "capture_source",
    "profile",
    "is_real_capture",
]


def _esp_packet(packet: Any) -> tuple[int, str, float, int] | None:
    if IP in packet and int(packet[IP].proto) == 50:
        payload = bytes(packet[IP].payload)
        source = packet[IP].src
    elif IPv6 in packet and int(packet[IPv6].nh) == 50:
        payload = bytes(packet[IPv6].payload)
        source = packet[IPv6].src
    elif UDP in packet and (
        int(packet[UDP].dport) == 4500 or int(packet[UDP].sport) == 4500
    ):
        payload = bytes(packet[UDP].payload)
        if payload.startswith(b"\x00\x00\x00\x00"):
            payload = payload[4:]
        source = packet[IP].src if IP in packet else packet[IPv6].src
    else:
        return None
    if (
        len(payload) >= 28
        and payload[17] >> 4 in (1, 2)
        and 28 <= struct.unpack_from("!I", payload, 24)[0] <= len(payload)
    ):
        return None
    if len(payload) < 8 or payload[0] == 0:
        return None
    return int.from_bytes(payload[:4], "big"), source, float(packet.time), len(packet)


def _traffic_type(label: str) -> str:
    parts = Path(label).stem.split("_")
    if len(parts) < 5 or not re.fullmatch(r"pfs-(?:on|off)", parts[2]):
        return ""
    traffic_type = re.sub(r"(?:[_-](?:run)?\d+)$", "", parts[-1])
    return traffic_type if re.fullmatch(r"[A-Za-z0-9-]+", traffic_type) else ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as capture:
        for chunk in iter(lambda: capture.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_flow_features(pcap_path: str, label: str) -> pd.DataFrame:
    """Return one feature row per ESP SPI, or an empty frame with stable columns."""
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file does not exist: {path}")
    capture_digest = _sha256(path)
    flows: dict[int, dict[str, Any]] = {}
    initiator_ip = None
    packet_errors = 0
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                try:
                    if UDP in packet and (
                        int(packet[UDP].dport) in (500, 4500)
                        or int(packet[UDP].sport) in (500, 4500)
                    ):
                        payload = bytes(packet[UDP].payload)
                        if (
                            int(packet[UDP].dport) == 4500
                            or int(packet[UDP].sport) == 4500
                        ) and payload.startswith(b"\x00\x00\x00\x00"):
                            payload = payload[4:]
                        if len(payload) >= 28 and payload[17] >> 4 in (1, 2):
                            source = (
                                packet[IP].src
                                if IP in packet
                                else packet[IPv6].src
                                if IPv6 in packet
                                else None
                            )
                            destination = (
                                packet[IP].dst
                                if IP in packet
                                else packet[IPv6].dst
                                if IPv6 in packet
                                else None
                            )
                            if source and initiator_ip is None:
                                initiator_ip = (
                                    source if payload[19] & 0x08 else destination
                                )
                    esp = _esp_packet(packet)
                    if esp is not None:
                        spi, source, timestamp, size = esp
                        flow = flows.get(spi)
                        if flow is None:
                            flows[spi] = {
                                "count": 1,
                                "size_sum": size,
                                "size_squared_sum": size * size,
                                "size_min": size,
                                "size_max": size,
                                "first_timestamp": timestamp,
                                "last_timestamp": timestamp,
                                "previous_timestamp": timestamp,
                                "iat_count": 0,
                                "iat_sum": 0.0,
                                "iat_squared_sum": 0.0,
                                "source": source,
                            }
                        else:
                            interval = max(0.0, timestamp - flow["previous_timestamp"])
                            flow["count"] += 1
                            flow["size_sum"] += size
                            flow["size_squared_sum"] += size * size
                            flow["size_min"] = min(flow["size_min"], size)
                            flow["size_max"] = max(flow["size_max"], size)
                            flow["last_timestamp"] = max(
                                flow["last_timestamp"], timestamp
                            )
                            flow["iat_count"] += 1
                            flow["iat_sum"] += interval
                            flow["iat_squared_sum"] += interval * interval
                            flow["previous_timestamp"] = timestamp
                except Exception:
                    packet_errors += 1
    except (OSError, EOFError) as exc:
        raise ValueError(f"Unable to read PCAP {path}: {exc}") from exc

    if packet_errors:
        raise ValueError(f"Failed to parse {packet_errors} packet(s) in {path}")
    rows = []
    for spi, flow in sorted(flows.items()):
        count = flow["count"]
        mean_size = flow["size_sum"] / count
        duration = flow["last_timestamp"] - flow["first_timestamp"]
        mean_iat = flow["iat_sum"] / flow["iat_count"] if flow["iat_count"] else 0.0
        iat_variance = (
            max(
                0.0,
                flow["iat_squared_sum"] / flow["iat_count"] - mean_iat * mean_iat,
            )
            if flow["iat_count"]
            else 0.0
        )
        source = flow["source"]
        reference_ip = initiator_ip or source
        rows.append(
            {
                "label": _traffic_type(label),
                "spi": f"0x{spi:08x}",
                "packet_count": count,
                "pkt_size_mean": mean_size,
                "pkt_size_std": math.sqrt(
                    max(
                        0.0,
                        flow["size_squared_sum"] / count - mean_size * mean_size,
                    )
                ),
                "pkt_size_min": flow["size_min"],
                "pkt_size_max": flow["size_max"],
                "iat_mean": mean_iat,
                "iat_std": math.sqrt(iat_variance),
                "flow_duration_seconds": float(duration),
                "packets_per_second": count / duration if duration > 0 else 0.0,
                "bytes_total": flow["size_sum"],
                "direction": "outbound" if source == reference_ip else "inbound",
                "capture_id": path.stem,
                "capture_file": path.name,
                "capture_sha256": capture_digest,
                "capture_source": "unverified",
                "is_real_capture": False,
            }
        )
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def build_feature_dataset(captures_dir: Path, output_path: Path) -> pd.DataFrame:
    """Rebuild the aggregate CSV and attach only hash-verified capture provenance."""
    manifest_path = output_path.parent / "capture_manifest.jsonl"
    manifest: dict[str, dict[str, Any]] = {}
    if manifest_path.is_file():
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

    frames = []
    for path in sorted(captures_dir.glob("*.pcap")):
        frame = extract_flow_features(str(path), path.name)
        if frame.empty:
            continue
        digest = frame["capture_sha256"].iloc[0]
        entry = manifest.get(path.name)
        verified_real = bool(
            entry
            and entry.get("is_real_capture") is True
            and entry.get("capture_sha256") == digest
            and isinstance(entry.get("source"), str)
            and entry["source"].strip()
            and isinstance(entry.get("traffic_type"), str)
            and entry["traffic_type"].strip()
        )
        if verified_real:
            frame["label"] = entry["traffic_type"].strip()
            frame["capture_source"] = entry["source"].strip()
            frame["profile"] = entry.get("profile")
            frame["is_real_capture"] = True
        frames.append(frame)
    dataset = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=FEATURE_COLUMNS)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(output_path, index=False)
    return dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Build ESP flow_features.csv from captures/*.pcap")
    parser.add_argument("--captures", type=Path, default=ROOT / "captures")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "flow_features.csv")
    args = parser.parse_args()
    dataset = build_feature_dataset(args.captures, args.output)
    print(f"Wrote {len(dataset)} ESP flow(s) to {args.output}")


if __name__ == "__main__":
    main()
