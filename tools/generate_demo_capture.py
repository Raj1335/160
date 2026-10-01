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
