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
    2: "DES",
    3: "3DES",
    11: "NULL",
    12: "AES-CBC",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM",
    1: "DES-CBC",
    0: "NONE",
}
_INTEGRITY = {
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    5: "AES-XCBC-MAC-96",
    8: "AES-CMAC-96",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
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
        "ike_failure_notifications": [],
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
    failure_notify_names = {14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD"}

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
                                            if payload_type == 41 and exchange == 34 and is_response:
                                                if len(body) < 4:
                                                    raise ValueError("truncated IKE notify payload")
                                                spi_size = body[1]
                                                if len(body) < 4 + spi_size:
                                                    raise ValueError("truncated IKE notify SPI")
                                                notify_type = struct.unpack_from("!H", body, 2)[0]
                                                notify_name = failure_notify_names.get(notify_type)
                                                if notify_name is not None:
                                                    facts["ike_failure_notifications"].append(
                                                        {
                                                            "type": notify_type,
                                                            "name": notify_name,
                                                            "packet": packet_index,
                                                        }
                                                    )
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

    if facts["ike_failure_notifications"]:
        facts["ike_sa_established"] = False
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
