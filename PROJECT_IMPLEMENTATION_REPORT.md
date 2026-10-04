> Historical design and implementation notes; this document is not the
> authoritative description of the current project. Use `README.md`.

# Project Implementation Report

> **Current status update (2026-10-01):** This report originally described the
> prototype before a genuine-data testbed existed. The current implementation
> additionally includes a strongSwan Docker testbed and collector, SHA-256-bound
> capture provenance, synthetic/unverified-data exclusion, capture-grouped
> cross-validation, held-out inference for training captures, and a Render
> deployment blueprint. The source snapshots and setup instructions later in
> this historical report are not authoritative; use `README.md` for current
> instructions. The current automated suite has 10 passing tests and the local
> Streamlit health endpoint returned HTTP 200. No genuine PCAPs or production
> model were generated in this environment because Docker is unavailable.

## 1. Objective and scope

This project was built from the specification in `SIH26160_Full_Pipeline_Spec.md` and the repository originally lacked the implementation scaffolding, code, capture/testbed assets, and supporting files. The goal was to create a working offline IPsec analyzer pipeline that:

- parses IKE metadata from a PCAP,
- extracts ESP flow statistics,
- computes honest traffic classification status in low-data conditions,
- scores a capture against a deterministic risk rule set,
- generates HTML reports, and
- exposes everything through a Streamlit dashboard.

Because the real Docker testbed and the `first_capture.pcap` were not present in the workspace, and Docker itself was unavailable here, the implementation includes a synthetic development PCAP generator to make the project runnable and testable locally. This synthetic capture is explicitly described as not being a real authenticated IPsec session and is not a substitute for genuine network validation.

---

## 2. What was built

The implementation includes the following major components:

- `parser/ike_parser.py` — best-effort IKE metadata extraction
- `features/esp_features.py` — ESP flow extraction with metadata-only statistics
- `ml/train_classifier.py` — honest, low-data-safe traffic classifier logic
- `scoring/rules.yaml` + `scoring/scorer.py` — deterministic risk scoring rules
- `report/template_combined.html` + `report/generate_report.py` — combined executive/technical HTML report generation
- `pipeline.py` — end-to-end analysis entry point
- `dashboard/app.py` — Streamlit UI for upload or existing-file analysis
- `tools/generate_demo_capture.py` — synthetic PCAP generation for development and smoke tests
- `tests/test_pipeline.py` — smoke tests and integration checks

---

## 3. Folder-by-folder summary

### Root folder

Files created or used here:

- `README.md`
- `requirements.txt`
- `.gitignore`
- `PROJECT_IMPLEMENTATION_REPORT.md` (this file)
- `pipeline.py`
- `SIH26160_Full_Pipeline_Spec.md`
- `captures/`
- `data/`
- `report/`
- `features/`
- `parser/`
- `ml/`
- `scoring/`
- `dashboard/`
- `tools/`
- `tests/`

### `parser/`

Purpose: IKE parsing and metadata extraction.

Contents:
- `__init__.py`
- `ike_parser.py`

### `features/`

Purpose: extraction of ESP flow-level packet statistics without decryption.

Contents:
- `__init__.py`
- `esp_features.py`

### `ml/`

Purpose: model training, evaluation logic, and inference entry points.

Contents:
- `__init__.py`
- `train_classifier.py`

### `scoring/`

Purpose: compliance/risk rules and score calculation.

Contents:
- `__init__.py`
- `rules.yaml`
- `scorer.py`

### `report/`

Purpose: HTML generation and the combined Jinja template.

Contents:
- `__init__.py`
- `template_combined.html`
- `generate_report.py`

### `dashboard/`

Purpose: Streamlit app to call the analysis pipeline.

Contents:
- `__init__.py`
- `app.py`

### `tools/`

Purpose: synthetic image/capture-generation support, used for local development and validation.

Contents:
- `__init__.py`
- `generate_demo_capture.py`

### `tests/`

Purpose: smoke and integration tests.

Contents:
- `test_pipeline.py`

### `captures/`

Contains empty placeholder and generated demo captures. It is intentionally not committed with real `.pcap` files.

### `data/`

Output folder for generated flow feature CSVs and parser outputs when running scripts.

### `reports/`

Output folder for generated HTML reports.

---

## 4. Actual code of each file

### `README.md`

```md
# IPsec Analyzer

An offline Python prototype that extracts observable IKE/ESP metadata from
packet captures, scores configured security findings, and creates a local HTML
report and Streamlit dashboard. It does not decrypt IKE or ESP payloads.

## What is included

- Streaming PCAP parsing and ESP-per-SPI packet size/timing features.
- IKEv2 SA_INIT transform extraction, with unknown/encrypted facts left unknown.
- A cross-validated Random Forest classifier that refuses to report accuracy
  when the labeled dataset is too small.
- YAML-based deterministic scoring, an HTML report, and a Streamlit UI.
- An explicitly synthetic PCAP generator and end-to-end smoke tests.

## Requirements and setup (Windows PowerShell)

Python 3.11 or newer and pip are required. A recent 64-bit Python installation
is recommended for the scientific Python packages. Docker is **not** required
to analyze existing PCAP files or run the synthetic smoke test.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, run the venv's interpreter
directly: `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.

## Run the analyzer

Place real `.pcap` files in `captures\`, then run:

```powershell
python pipeline.py captures\your_capture.pcap
```

The pipeline writes aggregate ESP features to `data\flow_features.csv`, IKE
facts when using the parser CLI, a trained model only when the dataset meets
the minimum evaluation requirements, and an HTML report in `reports\`.
Generated data, models, reports, and captures are ignored by Git.

Run the dashboard:

```powershell
python -m streamlit run dashboard\app.py
```

The dashboard defaults to captures in `captures\`, and also supports PCAP
uploads. Both routes call the same analysis pipeline.

## Synthetic development capture

This repository did not include the referenced `first_capture.pcap`, the
Docker testbed, or `SIH26160_Testbed_Automation_Spec.md`. For development and
tests only, make a structurally plausible fixture with:

```powershell
python tools\generate_demo_capture.py
python pipeline.py captures\demo_aesgcm256_pfs-on_ipv4_synthetic.pcap
```

**This generated PCAP is synthetic.** Its IKE_AUTH and ESP payload bytes do
not represent a real authenticated or encrypted IPsec tunnel. It exercises
packet framing, extraction, scoring, reporting, and UI integration; it is not
evidence of a working VPN and must not be presented as a real security
assessment. To validate real configuration facts and traffic classification,
use genuine captures made by the project's actual IPsec testbed. Docker was
not installed in the development environment, and the referenced testbed
specification was not supplied, so a real Docker VPN testbed could not be
verified or reproduced from the available files.

## Extract facts/features independently

```powershell
python -m parser.ike_parser
python -m features.esp_features
python -m ml.train_classifier
pytest -q
```

IKE attributes that are hidden inside encrypted IKE payloads (including
authentication method, some Child-SA details, and lifetimes) are reported as
unknown. PFS is unknown unless a parseable CREATE_CHILD_SA exchange is present.
The rule-based score is a prototype heuristic (100 means fewer triggered
findings), not a calibrated probability or production audit.

## Compliance references

Rules cite NIST SP 800-77 Rev. 1 and RFC 8221 as requested by the project
specification. Review the current guidance and your organization's policy
before relying on findings.
```

### `requirements.txt`

```txt
scapy
pandas
scikit-learn
joblib
PyYAML
Jinja2
streamlit
pytest
```

### `.gitignore`

```gitignore
__pycache__/
*.py[cod]
.pytest_cache/
.venv/
venv/
captures/*.pcap
data/*.csv
data/ike_facts/
ml/model.pkl
reports/*
!reports/.gitkeep
```

### `parser/__init__.py`

```python
"""IPsec IKE parsing."""
```

### `parser/ike_parser.py`

```python
"""Streaming, best-effort extraction of IKE and ESP metadata from PCAP files."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any

from scapy.all import IP, IPv6, UDP, PcapReader


ROOT = Path(__file__).resolve().parents[1]

_ENCRYPTION = {
    3: "3DES",
    12: "AES-CBC",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM",
    1: "DES-CBC",
    11: "3DES",
    0: "NONE",
}
_INTEGRITY = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    5: "HMAC-SHA2-256",
    6: "HMAC-SHA2-384",
    7: "HMAC-SHA2-512",
    12: "AES-XCBC-MAC-96",
    13: "AES-CMAC-96",
}
_PRF = {
    1: "PRF-HMAC-MD5",
    2: "PRF-HMAC-SHA1",
    5: "PRF-HMAC-SHA2-256",
    6: "PRF-HMAC-SHA2-384",
    7: "PRF-HMAC-SHA2-512",
}
_DH = {
    1: "MODP768",
    2: "MODP1024",
    5: "MODP1536",
    14: "MODP2048",
    15: "MODP3072",
    16: "MODP4096",
    19: "ECP256",
    20: "ECP384",
    21: "ECP521",
    31: "Curve25519",
}


def _ike_payloads(data: bytes, first_payload: int) -> list[tuple[int, bytes]]:
    """Walk an IKEv2 generic-payload chain without decrypting encrypted payloads."""
    payloads: list[tuple[int, bytes]] = []
    offset = 28
    payload_type = first_payload
    while payload_type and offset + 4 <= len(data):
        next_payload, _, length = struct.unpack_from("!BBH", data, offset)
        if length < 4 or offset + length > len(data):
            raise ValueError(f"invalid IKE payload length {length}")
        payloads.append((payload_type, data[offset + 4 : offset + length]))
        offset += length
        payload_type = next_payload
    return payloads


def _sa_transforms(body: bytes) -> dict[str, Any]:
    """Read transform IDs and TV-format key-length attributes from an SA payload."""
    result: dict[str, Any] = {}
    offset = 0
    while offset + 8 <= len(body):
        _, _, proposal_length, _, _, spi_size, transform_count = struct.unpack_from(
            "!BBHBBBB", body, offset
        )
        if proposal_length < 8 + spi_size or offset + proposal_length > len(body):
            raise ValueError("invalid IKE proposal length")
        transform_offset = offset + 8 + spi_size
        end = offset + proposal_length
        for _ in range(transform_count):
            if transform_offset + 8 > end:
                raise ValueError("truncated IKE transform")
            _, _, transform_length, transform_type, _, transform_id = struct.unpack_from(
                "!BBHBBH", body, transform_offset
            )
            if transform_length < 8 or transform_offset + transform_length > end:
                raise ValueError("invalid IKE transform length")
            key_length = None
            attr_offset = transform_offset + 8
            while attr_offset + 4 <= transform_offset + transform_length:
                attribute, value = struct.unpack_from("!HH", body, attr_offset)
                if attribute & 0x8000:
                    if (attribute & 0x7FFF) == 14:
                        key_length = value
                    attr_offset += 4
                else:
                    attribute_length = value
                    attr_offset += 4 + attribute_length
            if transform_type == 1:
                name = _ENCRYPTION.get(transform_id, f"Encryption transform {transform_id}")
                if name.startswith("AES-") and key_length:
                    name = f"{name}-{key_length}"
                result.setdefault("encryption_algorithm", name)
            elif transform_type == 2:
                result.setdefault("prf_algorithm", _PRF.get(transform_id, f"PRF transform {transform_id}"))
            elif transform_type == 3:
                if transform_id == 0:
                    result.setdefault("integrity_algorithm", "N/A (combined with AEAD)")
                else:
                    result.setdefault(
                        "integrity_algorithm",
                        _INTEGRITY.get(transform_id, f"Integrity transform {transform_id}"),
                    )
            elif transform_type == 4:
                result.setdefault("dh_group", _DH.get(transform_id, f"DH group {transform_id}"))
            transform_offset += transform_length
        offset = end
    return result


def _esp_info(packet: Any) -> tuple[int, str, str] | None:
    """Return SPI and endpoint addresses for a raw ESP packet."""
    if IP in packet and int(packet[IP].proto) == 50:
        payload = bytes(packet[IP].payload)
        source, destination = packet[IP].src, packet[IP].dst
    elif IPv6 in packet and int(packet[IPv6].nh) == 50:
        payload = bytes(packet[IPv6].payload)
        source, destination = packet[IPv6].src, packet[IPv6].dst
    elif UDP in packet and (
        int(packet[UDP].dport) == 4500 or int(packet[UDP].sport) == 4500
    ):
        payload = bytes(packet[UDP].payload)
        if payload.startswith(b"\x00\x00\x00\x00"):
            payload = payload[4:]
        source = packet[IP].src if IP in packet else packet[IPv6].src
        destination = packet[IP].dst if IP in packet else packet[IPv6].dst
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
    return struct.unpack_from("!I", payload)[0], source, destination


def _empty_facts() -> dict[str, Any]:
    return {
        "ike_version": None,
        "mode": None,
        "encryption_algorithm": None,
        "integrity_algorithm": None,
        "prf_algorithm": None,
        "dh_group": None,
        "pfs_enabled": None,
        "auth_method": None,
        "sa_lifetime_seconds": None,
        "initiator_ip": None,
        "responder_ip": None,
        "ike_sa_established": None,
        "child_sa_established": None,
        "spi_initiator": None,
        "spi_responder": None,
        "parse_warnings": [],
        "packets_total": 0,
        "packets_parsed": 0,
        "packets_failed": 0,
    }


def parse_ike(pcap_path: str) -> dict[str, Any]:
    """Extract observable IKE facts; encrypted or absent fields remain unknown."""
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file does not exist: {path}")

    facts = _empty_facts()
    auth_messages: dict[int, set[bool]] = {}
    child_dh_results: list[bool] = []
    selected_sa: dict[str, Any] | None = None
    offered_sa: dict[str, Any] | None = None
    first_ike_endpoints: tuple[str, str] | None = None
    esp_spi_by_source: dict[str, int] = {}

    try:
        with PcapReader(str(path)) as reader:
            for packet_index, packet in enumerate(reader, start=1):
                facts["packets_total"] += 1
                try:
                    packet_length = len(packet)
                    if packet_length <= 0:
                        raise ValueError("empty packet")
                    facts["packets_parsed"] += 1
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
                        if len(payload) >= 28:
                            version = payload[17]
                            exchange = payload[18]
                            message_id = struct.unpack_from("!I", payload, 20)[0]
                            message_length = struct.unpack_from("!I", payload, 24)[0]
                            if version >> 4 in (1, 2) and 28 <= message_length <= len(payload):
                                facts["ike_version"] = f"IKEv{version >> 4}"
                                if IP in packet:
                                    source, destination = packet[IP].src, packet[IP].dst
                                elif IPv6 in packet:
                                    source, destination = packet[IPv6].src, packet[IPv6].dst
                                else:
                                    source = destination = None
                                flags = payload[19]
                                is_response = bool(flags & 0x20)
                                if source and first_ike_endpoints is None:
                                    first_ike_endpoints = (
                                        (source, destination)
                                        if flags & 0x08
                                        else (destination, source)
                                    )
                                    facts["initiator_ip"], facts["responder_ip"] = first_ike_endpoints
                                if exchange == 35:
                                    auth_messages.setdefault(message_id, set()).add(is_response)
                                if version >> 4 == 2 and exchange in (34, 36):
                                    try:
                                        payloads = _ike_payloads(payload[:message_length], payload[16])
                                        for payload_type, body in payloads:
                                            if payload_type != 33:
                                                continue
                                            transforms = _sa_transforms(body)
                                            if exchange == 36:
                                                child_dh_results.append("dh_group" in transforms)
                                            elif exchange == 34 and transforms:
                                                if is_response:
                                                    selected_sa = transforms
                                                elif offered_sa is None:
                                                    offered_sa = transforms
                                    except ValueError as exc:
                                        facts["parse_warnings"].append(
                                            f"Packet {packet_index}: {exc}"
                                        )

                    esp = _esp_info(packet)
                    if esp is not None:
                        spi, source, _ = esp
                        esp_spi_by_source.setdefault(source, spi)
                except Exception as exc:
                    facts["packets_failed"] += 1
                    facts["parse_warnings"].append(f"Packet {packet_index}: {exc}")
    except (OSError, EOFError) as exc:
        raise ValueError(f"Unable to read PCAP {path}: {exc}") from exc

    if facts["ike_version"] == "IKEv2":
        transforms = selected_sa or offered_sa or {}
        facts.update(transforms)
        if facts["encryption_algorithm"] and "GCM" in facts["encryption_algorithm"]:
            facts["integrity_algorithm"] = "N/A (combined with AEAD)"
        if child_dh_results:
            facts["pfs_enabled"] = any(child_dh_results)
        else:
            facts["parse_warnings"].append(
                "PFS cannot be confirmed from this capture: no parseable CREATE_CHILD_SA exchange was observed."
            )

    auth_exchange_complete = any(
        responses == {False, True} for responses in auth_messages.values()
    )
    if esp_spi_by_source:
        facts["child_sa_established"] = True
        if auth_exchange_complete:
            facts["ike_sa_established"] = True
    if auth_messages and not auth_exchange_complete:
        facts["parse_warnings"].append(
            "No complete IKE_AUTH request/response pair was observed; establishment cannot be confirmed."
        )
    elif auth_messages and not esp_spi_by_source:
        facts["parse_warnings"].append(
            "IKE_AUTH completion alone cannot confirm authentication success because its payload is encrypted; establishment remains unknown without observed ESP traffic."
        )
    if first_ike_endpoints:
        initiator = first_ike_endpoints[0]
        facts["spi_initiator"] = (
            f"0x{esp_spi_by_source[initiator]:08x}" if initiator in esp_spi_by_source else None
        )
        responder_spis = [
            spi for source, spi in esp_spi_by_source.items() if source != initiator
        ]
        facts["spi_responder"] = f"0x{responder_spis[0]:08x}" if responder_spis else None
    elif esp_spi_by_source:
        observed_spis = list(esp_spi_by_source.values())
        facts["spi_initiator"] = f"0x{observed_spis[0]:08x}"
        facts["spi_responder"] = (
            f"0x{observed_spis[1]:08x}" if len(observed_spis) > 1 else None
        )
    return facts


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract IKE facts from captures/*.pcap")
    parser.add_argument("--captures", type=Path, default=ROOT / "captures")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "ike_facts")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    capture_paths = sorted(args.captures.glob("*.pcap"))
    if not capture_paths:
        parser.error(f"No .pcap files found in {args.captures}")
    for capture_path in capture_paths:
        facts = parse_ike(str(capture_path))
        output_path = args.output / f"ike_facts_{capture_path.stem}.json"
        output_path.write_text(json.dumps(facts, indent=2), encoding="utf-8")
        print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
```

### `features/__init__.py`

```python
"""ESP traffic feature extraction."""
```

### `features/esp_features.py`

```python
"""Extract non-decrypting packet timing and size features per ESP SPI."""

from __future__ import annotations

import argparse
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
    parts = label.removesuffix(".pcap").split("_")
    if len(parts) >= 5 and re.fullmatch(r"pfs-(?:on|off)", parts[2]):
        return parts[-1]
    return label


def extract_flow_features(pcap_path: str, label: str) -> pd.DataFrame:
    """Return one feature row per ESP SPI, or an empty frame with stable columns."""
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file does not exist: {path}")
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
            }
        )
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def build_feature_dataset(captures_dir: Path, output_path: Path) -> pd.DataFrame:
    """Rebuild the aggregate CSV from all named captures (idempotent)."""
    frames = [
        extract_flow_features(str(path), path.name)
        for path in sorted(captures_dir.glob("*.pcap"))
    ]
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
```

### `ml/__init__.py`

```python
"""Traffic classification."""
```

### `ml/train_classifier.py`

```python
"""Honest cross-validated traffic classifier with a safe untrained path."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_val_score


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "ml" / "model.pkl"
NON_FEATURE_COLUMNS = {"label", "spi", "direction", "traffic_type"}


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


def train_and_evaluate(csv_path: str = "./data/flow_features.csv") -> dict[str, Any]:
    """Cross-validate when each class supports it; otherwise report no metric."""
    path = Path(csv_path)
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        return _insufficient_result(0, 0)

    frame = pd.read_csv(path)
    label_column = "traffic_type" if "traffic_type" in frame.columns else "label"
    if label_column not in frame.columns:
        return _insufficient_result(0, 0)
    frame = frame.dropna(subset=[label_column])
    labels = frame[label_column].astype(str)
    n_samples = len(frame)
    n_classes = int(labels.nunique())
    if n_samples < 10 or n_classes < 2:
        return _insufficient_result(n_samples, n_classes)

    feature_columns = [
        column
        for column in frame.columns
        if column not in NON_FEATURE_COLUMNS
        and pd.api.types.is_numeric_dtype(frame[column])
    ]
    if not feature_columns:
        return {
            **_insufficient_result(n_samples, n_classes),
            "note": "No numeric flow features are available; classifier was not trained.",
        }

    features = frame[feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0)
    min_class_count = int(labels.value_counts().min())
    if min_class_count < 3:
        return _insufficient_result(n_samples, n_classes)
    folds = 5 if min_class_count >= 5 else 3
    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    predictions = cross_val_predict(model, features, labels, cv=splitter, n_jobs=1)
    fold_scores = cross_val_score(model, features, labels, cv=splitter, n_jobs=1)
    baseline = DummyClassifier(strategy="most_frequent")
    baseline_scores = cross_val_score(baseline, features, labels, cv=splitter, n_jobs=1)
    model.fit(features, labels)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_columns": feature_columns}, MODEL_PATH)

    matrix = confusion_matrix(labels, predictions, labels=model.classes_).tolist()
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
            f"Evaluated with {folds}-fold stratified cross-validation on "
            f"{n_samples} labeled flows. Demo/synthetic captures are not evidence "
            "of real-world performance."
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
    print(pd.Series(result).to_json(indent=2))


if __name__ == "__main__":
    main()
```

### `scoring/__init__.py`

```python
"""Deterministic IPsec compliance scoring."""
```

### `scoring/rules.yaml`

```yaml
rules:
  - id: weak_encryption
    category: Cryptographic Strength
    check_field: encryption_algorithm
    bad_values: ["DES", "3DES", "DES-CBC", "NULL"]
    severity: critical
    score_penalty: 80
    message: "Deprecated/weak encryption algorithm in use"

  - id: short_key_aes
    category: Cryptographic Strength
    check_field: encryption_algorithm
    bad_values: ["AES-CBC-128", "AES-GCM-128"]
    severity: low
    score_penalty: 5
    message: "AES-128 in use; AES-256 preferred for long-term security margin"

  - id: weak_dh_group
    category: Key Exchange Security
    check_field: dh_group
    bad_values: ["MODP768", "MODP1024", "MODP1536"]
    severity: high
    score_penalty: 40
    message: "Weak Diffie-Hellman group (<2048-bit equivalent) — vulnerable to precomputation attacks (Logjam-class)"

  - id: pfs_disabled
    category: Forward Secrecy
    check_field: pfs_enabled
    bad_values: [false]
    severity: medium
    score_penalty: 20
    message: "Perfect Forward Secrecy not confirmed/enabled — past sessions may be compromised if long-term key is leaked"

  - id: weak_integrity
    category: Cryptographic Strength
    check_field: integrity_algorithm
    bad_values: ["HMAC-MD5", "HMAC-SHA1", "NULL"]
    severity: medium
    score_penalty: 15
    message: "Weak or legacy integrity algorithm in use"

  - id: no_auth_detected
    category: Session Management
    check_field: ike_sa_established
    bad_values: [false]
    severity: critical
    score_penalty: 100
    message: "IKE SA failed to establish — tunnel not functional / auth failure"

  - id: long_sa_lifetime
    category: Session Management
    check_field: sa_lifetime_seconds
    bad_values: null
    severity: low
    score_penalty: 5
    message: "SA lifetime excessively long or undeclared — increases exposure window if key compromised"
```

### `scoring/scorer.py`

```python
"""Rule-based IPsec security scoring; unknown observations are not guessed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_RULES = ROOT / "scoring" / "rules.yaml"


def score_capture(
    ike_facts: dict[str, Any], rules_path: str = "scoring/rules.yaml"
) -> dict[str, Any]:
    """Apply configured penalties and the explicit critical-issue score cap."""
    path = Path(rules_path)
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        raise FileNotFoundError(f"Scoring rules file does not exist: {path}")
    with path.open(encoding="utf-8") as rules_file:
        configuration = yaml.safe_load(rules_file)
    rules = configuration.get("rules") if isinstance(configuration, dict) else None
    if not isinstance(rules, list):
        raise ValueError(f"Invalid scoring rules document: {path}")

    score = 100
    findings = []
    hard_cap = False
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Every scoring rule must be a mapping")
        rule_id = rule.get("id")
        field = rule.get("check_field")
        if not isinstance(rule_id, str) or not isinstance(field, str):
            raise ValueError("Every scoring rule needs string id and check_field")
        value = ike_facts.get(field)
        is_triggered = False
        if rule_id == "long_sa_lifetime":
            is_triggered = value is None or (
                isinstance(value, (int, float)) and value > 86400
            )
        elif value is not None:
            bad_values = rule.get("bad_values") or []
            is_triggered = any(
                value == bad
                or (
                    isinstance(value, str)
                    and isinstance(bad, str)
                    and value.casefold() == bad.casefold()
                )
                for bad in bad_values
            )
        if not is_triggered:
            continue
        penalty = rule.get("score_penalty")
        if not isinstance(penalty, int) or penalty < 0:
            raise ValueError(f"Invalid score_penalty in scoring rule {rule_id}")
        score -= penalty
        hard_cap = hard_cap or rule_id in {"weak_encryption", "no_auth_detected"}
        findings.append(
            {
                "id": rule_id,
                "severity": rule.get("severity", "unknown"),
                "message": rule.get("message", ""),
                "field": field,
                "observed_value": value,
                "category": rule.get("category", "Session Management"),
            }
        )
    score = max(0, score)
    if hard_cap:
        score = min(score, 20)
    threat_matrix = [
        {
            "category": finding["category"],
            "severity": finding["severity"],
            "description": finding["message"],
        }
        for finding in findings
    ]
    return {"risk_score": score, "findings": findings, "threat_matrix": threat_matrix}
```

### `report/__init__.py`

```python
"""HTML report generation."""
```

### `report/template_combined.html`

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IPsec Analysis — {{ label }}</title>
  <style>
    :root { color-scheme: light; --ink: #182230; --muted: #526174; --line: #d6dee8; --panel: #f4f7fb; }
    body { margin: 0 auto; max-width: 1050px; padding: 2rem; color: var(--ink); font: 16px/1.55 system-ui, sans-serif; }
    h1, h2 { line-height: 1.2; } h2 { margin-top: 2rem; border-bottom: 1px solid var(--line); padding-bottom: .4rem; }
    .score { display: inline-block; padding: .7rem 1.3rem; border-radius: .75rem; color: white; font-size: 2.5rem; font-weight: 750; }
    .red { background: #a62b2b; } .yellow { background: #916400; } .green { background: #187346; }
    .banner { padding: 1rem; border-left: 5px solid #b47700; background: #fff6d9; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { border: 1px solid var(--line); padding: .55rem .7rem; text-align: left; overflow-wrap: anywhere; }
    th { background: var(--panel); } .critical { background: #fde9e7; } .high { background: #fff0df; }
    .medium { background: #fff8d9; } .low { background: #edf4ff; }
    code, pre { white-space: pre-wrap; overflow-wrap: anywhere; } footer { margin-top: 2rem; color: var(--muted); font-size: .9rem; }
    @media print { body { max-width: none; padding: 0; } }
  </style>
</head>
<body>
  <header>
    <p>IPsec configuration and traffic analysis</p>
    <h1>{{ label }}</h1>
    <p>Analyzed {{ analyzed_at }}</p>
    <div class="score {{ score_color }}">{{ score_result.risk_score }}<small> / 100</small></div>
    <p>Higher scores indicate fewer triggered findings; this is a prototype rule score, not a risk probability.</p>
  </header>
  <section>
    <h2>Executive Summary</h2>
    {% for sentence in executive_summary %}<p>{{ sentence }}</p>{% endfor %}
  </section>
  <section>
    <h2>Threat Matrix</h2>
    {% if score_result.threat_matrix %}
    <table>
      <thead><tr><th>Category</th><th>Severity</th><th>Description</th></tr></thead>
      <tbody>{% for finding in score_result.threat_matrix %}
      <tr class="{{ finding.severity }}"><td>{{ finding.category }}</td><td>{{ finding.severity|upper }}</td><td>{{ finding.description }}</td></tr>
      {% endfor %}</tbody>
    </table>
    {% else %}<p>No configured security rules were triggered by observed values. Unknown fields are not treated as confirmed-safe.</p>{% endif %}
  </section>
  <section>
    <h2>Technical Detail</h2>
    <table><thead><tr><th>Field</th><th>Observed value</th></tr></thead><tbody>
      {% for name, value in ike_facts.items() %}
      <tr><th>{{ name|replace("_", " ")|title }}</th><td><code>{{ value if value is not none else "Unknown / not observable" }}</code></td></tr>
      {% endfor %}
    </tbody></table>
  </section>
  <section>
    <h2>Traffic Classification</h2>
    {% if classifier_training.status == "insufficient_data" %}
      <p class="banner"><strong>Classifier not yet validated — insufficient training data.</strong> {{ classifier_training.note }}</p>
    {% else %}
      <p>{{ classifier_training.note }}</p>
      <p>Cross-validation accuracy: {{ "%.3f"|format(classifier_training.cv_accuracy_mean) }}; majority baseline: {{ "%.3f"|format(classifier_training.baseline_majority_accuracy) }}.</p>
    {% endif %}
    <p>Flow prediction: {{ classifier_result.predicted_label if classifier_result.predicted_label else "Not available" }}</p>
    <h3>AI Confidence Score</h3>
    {% if classifier_result.confidence is not none %}
      <p>{{ "%.1f"|format(classifier_result.confidence * 100) }}%</p>
    {% else %}
      <p>N/A — {{ classifier_result.note }}</p>
    {% endif %}
  </section>
  <footer>
    <p>Compliance reference basis: NIST SP 800-77 Rev. 1 and RFC 8221. This is a prototype/lab analysis, not a production security audit. Packet captures reveal only observable metadata; encrypted IKE payloads are not decrypted.</p>
  </footer>
</body>
</html>
```

### `report/generate_report.py`

```python
"""Render the combined executive and technical HTML report."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "report"


def generate_report(
    label: str,
    ike_facts: dict[str, Any],
    classifier_result: dict[str, Any],
    score_result: dict[str, Any],
    output_dir: str = "./reports/",
) -> str:
    """Write an HTML report and return its absolute path."""
    output_path = Path(output_dir)
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    output_path.mkdir(parents=True, exist_ok=True)

    score = score_result["risk_score"]
    score_color = "red" if score < 40 else "yellow" if score <= 70 else "green"
    encryption = ike_facts.get("encryption_algorithm") or "an unknown encryption algorithm"
    dh_group = ike_facts.get("dh_group") or "an unknown key-exchange group"
    findings = score_result.get("findings", [])
    critical = next(
        (finding["message"] for finding in findings if finding["severity"] == "critical"),
        None,
    )
    concerns = (
        f"{len(findings)} configured security concern(s) were identified"
        if findings
        else "No configured security rules were triggered by observed values"
    )
    summary = [
        f"This capture reports {encryption} and {dh_group}; unavailable facts remain unknown rather than inferred.",
        f"{concerns}{f', including {critical}' if critical else ''}.",
        f"The resulting prototype security score is {score}/100.",
        "Encrypted IKE payloads were not decrypted; review the technical details and capture limitations before drawing conclusions.",
    ]
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(("html", "xml")),
    )
    template = environment.get_template("template_combined.html")
    classifier_training = classifier_result.get("training", classifier_result)
    prediction = {
        "predicted_label": classifier_result.get("predicted_label"),
        "confidence": classifier_result.get("confidence"),
        "note": classifier_result.get("note", "No classifier prediction is available."),
    }
    html = template.render(
        label=label,
        analyzed_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        score_color=score_color,
        score_result=score_result,
        ike_facts=ike_facts,
        classifier_result=prediction,
        classifier_training=classifier_training,
        executive_summary=summary,
    )
    path = output_path / f"report_{Path(label).stem}.html"
    path.write_text(html, encoding="utf-8")
    return str(path)
```

### `pipeline.py`

```python
"""Orchestrate one capture through parsing, features, scoring, and reporting."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd

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

    dataset = build_feature_dataset(ROOT / "captures", ROOT / "data" / "flow_features.csv")
    try:
        same_capture = capture.resolve().parent == (ROOT / "captures").resolve()
    except OSError:
        same_capture = False
    if not same_capture:
        dataset = pd.concat([dataset, flow_features], ignore_index=True)
        with tempfile.TemporaryDirectory(prefix="ipsec-training-") as temp_dir:
            training_csv = Path(temp_dir) / "flow_features.csv"
            dataset.to_csv(training_csv, index=False)
            training = train_and_evaluate(str(training_csv))
    else:
        training = train_and_evaluate(str(ROOT / "data" / "flow_features.csv"))
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
```

### `dashboard/__init__.py`

```python
"""Streamlit dashboard."""
```

### `dashboard/app.py`

```python
"""Streamlit UI for selecting, analyzing, and downloading capture reports."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import streamlit as st

from pipeline import ROOT, analyze


CAPTURES_DIR = ROOT / "captures"


def _show_results(result: dict) -> None:
    st.subheader(f"Analysis: {result['label']}")
    score = result["score_result"]["risk_score"]
    st.metric("Security score (higher is better)", f"{score} / 100")
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
    report_path = Path(result["report_path"])
    st.download_button(
        "Download HTML report",
        data=report_path.read_bytes(),
        file_name=report_path.name,
        mime="text/html",
    )


def main() -> None:
    st.set_page_config(page_title="IPsec Analyzer", page_icon="🔐", layout="wide")
    st.title("IPsec Configuration Analyzer")
    st.caption(
        "Offline capture analysis. Encrypted IKE payloads are not decrypted; "
        "unknown values are not guessed."
    )
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
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
            cache_key = str(selected_path.resolve())
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
            except (OSError, ValueError) as exc:
                st.error(f"Capture analysis failed: {exc}")
                st.stop()
        result = st.session_state.get("analysis_result")
        if result:
            _show_results(result)


if __name__ == "__main__":
    main()
```

### `tools/__init__.py`

```python
"""Project utilities."""
```

### `tools/generate_demo_capture.py`

```python
"""Generate a clearly synthetic, structurally plausible IKE/ESP PCAP fixture."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from scapy.all import Ether, IP, Raw, UDP, wrpcap


def _ike_message(
    exchange: int,
    flags: int,
    message_id: int,
    first_payload: int,
    payload: bytes,
    initiator_spi: bytes,
    responder_spi: bytes,
) -> bytes:
    length = 28 + len(payload)
    header = struct.pack(
        "!8s8sBBBBII",
        initiator_spi,
        responder_spi,
        first_payload,
        0x20,
        exchange,
        flags,
        message_id,
        length,
    )
    return header + payload


def _sa_payload() -> bytes:
    transforms = [
        (3, 1, 20, struct.pack("!HH", 0x800E, 256)),
        (3, 2, 5, b""),
        (3, 3, 0, b""),
        (0, 4, 14, b""),
    ]
    encoded = bytearray()
    for last, transform_type, transform_id, attributes in transforms:
        length = 8 + len(attributes)
        encoded.extend(
            struct.pack("!BBHBBH", last, 0, length, transform_type, 0, transform_id)
        )
        encoded.extend(attributes)
    proposal_length = 8 + len(encoded)
    proposal = struct.pack(
        "!BBHBBBB", 0, 0, proposal_length, 1, 1, 0, len(transforms)
    ) + encoded
    sa_body = bytes(proposal)
    return struct.pack("!BBH", 0, 0, 4 + len(sa_body)) + sa_body


def generate_demo_capture(output_path: Path) -> Path:
    """Write sample framing/metadata; payload bytes do not represent a real tunnel."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    initiator_spi = bytes.fromhex("1122334455667788")
    responder_spi = bytes.fromhex("8877665544332211")
    packets = []
    timestamp = 1_780_000_000.0

    for is_response in (False, True):
        flags = 0x20 if is_response else 0x08
        ike_init = _ike_message(
            34, flags, 0, 33, _sa_payload(), initiator_spi, responder_spi
        )
        source, destination = (
            ("10.0.0.2", "10.0.0.1")
            if is_response
            else ("10.0.0.1", "10.0.0.2")
        )
        packet = (
            Ether()
            / IP(src=source, dst=destination)
            / UDP(sport=500, dport=500)
            / Raw(load=ike_init)
        )
        packet.time = timestamp
        timestamp += 0.02
        packets.append(packet)

        encrypted_body = bytes((0xA0 + index) % 256 for index in range(32))
        encrypted_payload = struct.pack("!BBH", 0, 0, 4 + len(encrypted_body)) + encrypted_body
        ike_auth = _ike_message(
            35, flags, 1, 46, encrypted_payload, initiator_spi, responder_spi
        )
        packet = (
            Ether()
            / IP(src=source, dst=destination)
            / UDP(sport=500, dport=500)
            / Raw(load=ike_auth)
        )
        packet.time = timestamp
        timestamp += 0.02
        packets.append(packet)

    for is_initiator in (True, False):
        source, destination = (
            ("10.0.0.1", "10.0.0.2")
            if is_initiator
            else ("10.0.0.2", "10.0.0.1")
        )
        spi = 0xA1B2C3D4 if is_initiator else 0xE5F6A7B8
        for sequence, content_length in enumerate((48, 96, 160, 72), start=1):
            esp_payload = struct.pack("!II", spi, sequence) + bytes(
                (sequence + index) % 256 for index in range(content_length)
            )
            packet = (
                Ether()
                / IP(src=source, dst=destination, proto=50)
                / Raw(load=esp_payload)
            )
            packet.time = timestamp
            timestamp += 0.05
            packets.append(packet)

    wrpcap(str(output_path), packets)
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a synthetic PCAP for development only (not real IPsec traffic)."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "captures"
        / "demo_aesgcm256_pfs-on_ipv4_synthetic.pcap",
    )
    args = parser.parse_args()
    output_path = generate_demo_capture(args.output)
    print(f"Wrote synthetic PCAP: {output_path}")
    print("This file is not a real IKE authentication or encrypted IPsec session.")


if __name__ == "__main__":
    main()
```

### `tests/test_pipeline.py`

```python
from __future__ import annotations

import struct
from pathlib import Path

import pandas as pd

from features.esp_features import FEATURE_COLUMNS, extract_flow_features
from ml.train_classifier import predict_traffic_type, train_and_evaluate
import ml.train_classifier as classifier
import pipeline
from parser.ike_parser import parse_ike
from scoring.scorer import score_capture
from tools.generate_demo_capture import generate_demo_capture
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
    assert 0 <= score["risk_score"] <= 100
    assert any(finding["id"] == "long_sa_lifetime" for finding in score["findings"])

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
    report_html = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "Classifier not yet validated" in report_html


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
    assert result["risk_score"] == 20
    assert result["findings"][0]["id"] == "weak_encryption"


def test_classifier_handles_missing_training_csv(tmp_path):
    result = train_and_evaluate(str(tmp_path / "missing.csv"))
    assert result["status"] == "insufficient_data"
    assert result["n_samples"] == 0


def test_classifier_trains_only_with_evaluable_data(tmp_path, monkeypatch):
    training_csv = tmp_path / "training.csv"
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
    assert result["status"] == "trained"
    assert result["cv_accuracy_std"] is not None
    assert result["baseline_majority_accuracy"] is not None
    prediction = predict_traffic_type(rows[0])
    assert prediction["predicted_label"] in {"bulk", "icmp"}
    assert 0 <= prediction["confidence"] <= 1


def test_feature_extractor_returns_stable_empty_frame(tmp_path):
    capture = tmp_path / "no_esp.pcap"
    wrpcap(str(capture), [Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP()])
    frame = extract_flow_features(str(capture), capture.name)
    assert list(frame.columns) == FEATURE_COLUMNS
    assert frame.empty


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
```

---

## 5. Validation and execution summary

I ran the following checks successfully:

### Dependencies and environment validation

- Python 3.14 environment created
- `requirements.txt` installed into `.venv`
- `pip check` passed
- Streamlit installed and verified with `streamlit --version`

### Smoke tests and integration validation

The project was validated with:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Result:

```txt
......                                                                   [100%]
6 passed in 23.93s
```

### Dashboard validation

The app was also started in headless mode and a health check succeeded via HTTP 200:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.headless true --server.port 18999 --server.address 127.0.0.1
```

Health response:

```txt
Streamlit health: HTTP 200 ok
```

### Python compile check

```powershell
python -m compileall -q parser features ml scoring report dashboard tools tests pipeline.py
```

Result:

```txt
Python syntax compilation succeeded.
```

---

## 6. Implementation notes and limitations

The implementation intentionally follows the spec in a conservative and honest manner:

- fields hidden inside encrypted IKE payloads are left unknown instead of guessed,
- classification is not reported as valid when the data is too small,
- the score is a deterministic rule-based heuristic rather than a calibrated production risk model,
- the dashboard is designed to work with either a directory capture or uploaded PCAP.

The largest real-world limitation is that the repository did not include:

- the Docker testbed,
- the actual `first_capture.pcap`,
- the actual packet matrix or the reference capture set,
- the upstream spec file for the Docker automations.

Because of this, the project was successfully implemented and tested locally with a synthetic capture generator, but it has not been verified against real IKE/IPsec traffic from the intended testbed. The synthetic capture is valuable for software validation, not as evidence of real-world IPsec behavior.

---

## 7. Final status

The local end-to-end application, test suite, and Render deployment configuration
are implemented. Real-data generation is now reproducible through
`tools/collect_real_dataset.py` and the strongSwan configuration under
`testbed/`. The collector has **not** been executed here: Docker is not installed
in this environment. Therefore the workspace contains no genuine labeled
captures, no real-data evaluation metrics, and no trained production model.
Run the collector on a Docker-enabled machine before claiming real-data
validation or classifier performance. See `README.md` for the current workflow
and hosting limitations.
