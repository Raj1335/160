"""Capture genuine, locally negotiated strongSwan IPsec traffic with Docker."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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
PROFILES_DIR = ROOT / "testbed" / "profiles"
SOURCE = "strongswan-docker-testbed"
_COMPOSE_COMMAND: tuple[str, ...] | None = None


def _compose_command() -> tuple[str, ...]:
    """Resolve Docker Compose v2 or the standalone docker-compose command."""
    global _COMPOSE_COMMAND
    if _COMPOSE_COMMAND is not None:
        return _COMPOSE_COMMAND

    docker = shutil.which("docker")
    if docker is not None:
        result = subprocess.run(
            [docker, "compose", "version"],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            _COMPOSE_COMMAND = (docker, "compose")
            return _COMPOSE_COMMAND

    standalone = shutil.which("docker-compose")
    if standalone is not None:
        result = subprocess.run(
            [standalone, "version"],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            _COMPOSE_COMMAND = (standalone,)
            return _COMPOSE_COMMAND

    raise RuntimeError(
        "Docker Compose was not found. Install the Docker Compose v2 plugin "
        "or the standalone docker-compose command."
    )


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [*_compose_command(), "-f", str(COMPOSE_FILE), *args],
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


def _load_profile(name: str) -> dict[str, Any]:
    """Load and validate the metadata for a named strongSwan profile."""
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", name) is None:
        raise ValueError(f"Invalid profile name: {name!r}")
    profile_dir = PROFILES_DIR / name
    metadata_path = profile_dir / "metadata.json"
    if not metadata_path.is_file():
        available = sorted(
            path.name for path in PROFILES_DIR.iterdir() if path.is_dir()
        ) if PROFILES_DIR.is_dir() else []
        raise ValueError(
            f"Unknown profile {name!r}. Available profiles: {', '.join(available)}"
        )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    required = {
        "name",
        "ike_version",
        "mode",
        "auth",
        "pfs",
        "expected_grade",
        "expected_findings",
    }
    if not isinstance(metadata, dict) or not required.issubset(metadata):
        raise ValueError(f"Profile metadata is incomplete: {metadata_path}")
    for endpoint in ("west.conf", "east.conf"):
        if not (profile_dir / endpoint).is_file():
            raise FileNotFoundError(f"Profile is missing {endpoint}: {profile_dir}")
    if metadata["name"] != name or metadata["mode"] != "tunnel":
        raise ValueError(f"Profile metadata does not match profile directory: {name}")
    if not isinstance(metadata["pfs"], bool) or not isinstance(
        metadata["expected_findings"], list
    ):
        raise ValueError(f"Invalid PFS or expected_findings value in {metadata_path}")
    return metadata


def _activate_profile(name: str) -> None:
    """Install both endpoint configs and restart strongSwan for the profile."""
    for service in ("west", "east"):
        _exec(
            service,
            f"cp /profiles/{name}/{service}.conf /etc/ipsec.conf && ipsec restart",
        )


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
    profile: str,
    metadata: dict[str, Any],
    traffic_type: str,
    run_number: int,
    duration_seconds: int,
) -> dict[str, Any]:
    pfs_state = "on" if metadata["pfs"] else "off"
    filename = (
        f"ipsec_{profile}_pfs-{pfs_state}_ipv4_"
        f"{traffic_type}-run{run_number:02d}.pcap"
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
        ike_facts["ike_version"] != metadata["ike_version"]
        or ike_facts["child_sa_established"] is not True
        or flows.empty
    ):
        raise RuntimeError(
            f"Capture validation failed for {filename}: expected an observed "
            f"{metadata['ike_version']} "
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
        "profile": profile,
        "expected_grade": metadata["expected_grade"],
        "expected_findings": metadata["expected_findings"],
        "ike_version": metadata["ike_version"],
        "mode": metadata["mode"],
        "auth": metadata["auth"],
        "pfs": metadata["pfs"],
        "pfs_configured": metadata["pfs"],
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


def collect(
    repetitions: int = 3,
    duration_seconds: int = 10,
    profile: str | None = None,
) -> list[dict[str, Any]]:
    if repetitions < 3:
        raise ValueError("At least 3 independent repetitions per traffic class are required.")
    if duration_seconds < 3:
        raise ValueError("The bulk traffic duration must be at least 3 seconds.")
    if profile:
        profile_names = [profile]
    else:
        profile_names = sorted(
            path.name for path in PROFILES_DIR.iterdir() if path.is_dir()
        )
    if not profile_names:
        raise ValueError(f"No testbed profiles found in {PROFILES_DIR}")
    profile_metadata = {name: _load_profile(name) for name in profile_names}
    _compose_command()

    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing_captures = [
        CAPTURES_DIR
        / (
            f"ipsec_{profile_name}_pfs-"
            f"{'on' if metadata['pfs'] else 'off'}_ipv4_"
            f"{traffic_type}-run{run_number:02d}.pcap"
        )
        for profile_name, metadata in profile_metadata.items()
        for traffic_type in TRAFFIC_TYPES
        for run_number in range(1, repetitions + 1)
    ]
    conflicts = [path.name for path in existing_captures if path.exists()]
    if conflicts:
        raise FileExistsError(
            "Refusing to overwrite existing capture(s): " + ", ".join(conflicts)
        )
    records = []
    try:
        _run("up", "-d", "--build")
        _prepare_lab()
        for profile_name, metadata in profile_metadata.items():
            _activate_profile(profile_name)
            for traffic_type in TRAFFIC_TYPES:
                for run_number in range(1, repetitions + 1):
                    record = _capture_one(
                        profile_name,
                        metadata,
                        traffic_type,
                        run_number,
                        duration_seconds,
                    )
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
            "Build labeled PCAPs from real strongSwan tunnel profiles. "
            "At least three runs per traffic class are required."
        )
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--duration-seconds", type=int, default=10)
    parser.add_argument(
        "--profile",
        help="Run one named profile instead of the full profile matrix",
    )
    args = parser.parse_args()
    try:
        records = collect(args.repetitions, args.duration_seconds, args.profile)
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
