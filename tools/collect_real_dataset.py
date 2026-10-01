"""Capture genuine, locally negotiated strongSwan IPsec traffic with Docker."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from features.esp_features import extract_flow_features
from parser.ike_parser import parse_ike


COMPOSE_FILE = ROOT / "testbed" / "docker-compose.yml"
CAPTURES_DIR = ROOT / "captures"
MANIFEST_PATH = ROOT / "data" / "capture_manifest.jsonl"
TRAFFIC_TYPES = ("icmp", "web", "bulk")
SOURCE = "strongswan-docker-testbed"


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        check=False,
        text=True,
        capture_output=True,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Docker Compose {' '.join(args)} failed: {detail}")
    return result


def _exec(service: str, command: str, *, check: bool = True) -> str:
    result = _run("exec", "-T", service, "sh", "-c", command, check=check)
    return result.stdout.strip()


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as capture:
        for chunk in iter(lambda: capture.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _prepare_lab() -> None:
    _exec(
        "west",
        "ip addr show dev lo | grep -q '10.10.1.1/32' || "
        "ip addr add 10.10.1.1/32 dev lo; ipsec start",
    )
    _exec(
        "east",
        "ip addr show dev lo | grep -q '10.10.2.1/32' || "
        "ip addr add 10.10.2.1/32 dev lo; ipsec start; "
        "iperf3 -s -B 10.10.2.1 -D",
    )
    _run(
        "exec",
        "-T",
        "-d",
        "east",
        "python3",
        "-m",
        "http.server",
        "8080",
        "--bind",
        "10.10.2.1",
    )


def _generate_traffic(traffic_type: str, duration_seconds: int) -> str:
    if traffic_type == "icmp":
        return _exec("west", "ping -I 10.10.1.1 -c 40 -i 0.1 10.10.2.1")
    if traffic_type == "web":
        return _exec(
            "west",
            "i=0; while [ $i -lt 40 ]; do "
            "curl --interface 10.10.1.1 -fsS -o /dev/null "
            "http://10.10.2.1:8080/; i=$((i+1)); done",
        )
    if traffic_type == "bulk":
        return _exec(
            "west",
            f"iperf3 -c 10.10.2.1 -B 10.10.1.1 -t {duration_seconds} -P 2",
        )
    raise ValueError(f"Unsupported traffic type: {traffic_type}")


def _capture_one(
    traffic_type: str, run_number: int, duration_seconds: int
) -> dict[str, Any]:
    filename = (
        f"tunnel_aesgcm256_pfs-on_ipv4_{traffic_type}-run{run_number:02d}.pcap"
    )
    output_path = CAPTURES_DIR / filename
    _exec(
        "west",
        "tcpdump -U -n -i eth0 -w "
        f"/captures/{filename} "
        "'udp port 500 or udp port 4500 or ip proto 50' "
        ">/tmp/ipsec-analyzer-tcpdump.log 2>&1 & "
        "echo $! >/tmp/ipsec-analyzer-tcpdump.pid",
    )
    time.sleep(1)
    _exec("west", "ipsec down lab", check=False)
    tunnel = _exec("west", "ipsec up lab")
    traffic_output = _generate_traffic(traffic_type, duration_seconds)
    time.sleep(1)
    _exec(
        "west",
        "kill -INT \"$(cat /tmp/ipsec-analyzer-tcpdump.pid)\"; sleep 1",
    )
    if not output_path.is_file() or output_path.stat().st_size == 0:
        raise RuntimeError(f"strongSwan produced no packet capture: {output_path}")

    ike_facts = parse_ike(str(output_path))
    flows = extract_flow_features(str(output_path), filename)
    if (
        ike_facts["ike_version"] != "IKEv2"
        or ike_facts["child_sa_established"] is not True
        or flows.empty
    ):
        raise RuntimeError(
            f"Capture validation failed for {filename}: expected an observed IKEv2 "
            "exchange and established Child SA/ESP traffic "
            f"(IKE={ike_facts['ike_version']!r}, "
            f"Child SA={ike_facts['child_sa_established']!r}, "
            f"ESP flows={len(flows)}). "
            "Check the strongSwan logs and Docker host IPsec support."
        )

    return {
        "capture_file": filename,
        "capture_sha256": _digest(output_path),
        "source": SOURCE,
        "is_real_capture": True,
        "traffic_type": traffic_type,
        "mode": "tunnel",
        "encryption_algorithm_configured": "AES-GCM-256",
        "pfs_configured": True,
        "ip_version": "ipv4",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "ike_facts": {
            "ike_version": ike_facts["ike_version"],
            "child_sa_established": ike_facts["child_sa_established"],
            "esp_flow_count": len(flows),
        },
        "traffic_command_output": traffic_output[-500:],
        "tunnel_negotiation_output": tunnel[-500:],
    }


def collect(repetitions: int = 3, duration_seconds: int = 10) -> list[dict[str, Any]]:
    if repetitions < 3:
        raise ValueError("At least 3 independent repetitions per traffic class are required.")
    if duration_seconds < 3:
        raise ValueError("The bulk traffic duration must be at least 3 seconds.")
    if shutil.which("docker") is None:
        raise RuntimeError(
            "Docker was not found. Install Docker Desktop with Linux containers "
            "enabled, then rerun this command."
        )
    version = subprocess.run(
        ["docker", "compose", "version"],
        check=False,
        text=True,
        capture_output=True,
    )
    if version.returncode:
        raise RuntimeError("Docker Compose v2 is required: " + version.stderr.strip())

    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    records = []
    try:
        _run("up", "-d", "--build")
        _prepare_lab()
        for traffic_type in TRAFFIC_TYPES:
            for run_number in range(1, repetitions + 1):
                record = _capture_one(traffic_type, run_number, duration_seconds)
                records.append(record)
                print(
                    f"Captured {record['capture_file']} "
                    f"({record['ike_facts']['esp_flow_count']} ESP flows)"
                )
    finally:
        _run("down", check=False)

    existing = []
    if MANIFEST_PATH.is_file():
        existing = [
            json.loads(line)
            for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    by_name = {entry["capture_file"]: entry for entry in existing}
    by_name.update({entry["capture_file"]: entry for entry in records})
    MANIFEST_PATH.write_text(
        "".join(
            json.dumps(by_name[name], sort_keys=True) + "\n"
            for name in sorted(by_name)
        ),
        encoding="utf-8",
    )
    return records


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build labeled PCAPs from real strongSwan IKEv2 tunnels. "
            "At least three runs per traffic class are required."
        )
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--duration-seconds", type=int, default=10)
    args = parser.parse_args()
    try:
        records = collect(args.repetitions, args.duration_seconds)
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"Real-data collection failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Wrote {len(records)} validated real captures and provenance to "
        f"{MANIFEST_PATH}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
