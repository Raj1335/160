"""Register a documented real IKEv2/ESP capture as labeled training input."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from features.esp_features import extract_flow_features
from ipsec_parser.ike_parser import parse_ike

CAPTURES_DIR = ROOT / "captures"
MANIFEST_PATH = ROOT / "data" / "capture_manifest.jsonl"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as capture:
        for chunk in iter(lambda: capture.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def register_capture(
    source_path: Path,
    traffic_type: str,
    provenance: str,
    license_name: str,
    *,
    attest_real_capture: bool,
) -> Path:
    """Validate, copy, and manifest-register one user-attested capture."""
    source_path = source_path.expanduser().resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"Capture file does not exist: {source_path}")
    if source_path.suffix.casefold() not in {".pcap", ".pcapng"}:
        raise ValueError("Capture file must have a .pcap or .pcapng extension.")
    if not attest_real_capture:
        raise ValueError(
            "Refusing to register training data without explicit real-capture "
            "attestation. Add --attest-real-capture only for genuine captured "
            "traffic you are authorized to use."
        )
    traffic_type = traffic_type.strip().casefold()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", traffic_type):
        raise ValueError("Traffic type must be a short, non-empty label.")
    provenance = provenance.strip()
    license_name = license_name.strip()
    if not provenance:
        raise ValueError(
            "Provide a source URL, experiment record, or other provenance citation."
        )
    if not license_name:
        raise ValueError("Provide the capture license or permission basis.")

    facts = parse_ike(str(source_path))
    flows = extract_flow_features(str(source_path), source_path.name)
    if facts["ike_version"] != "IKEv2" or facts["child_sa_established"] is not True:
        raise ValueError(
            "Capture must contain observable IKEv2 and established Child-SA/ESP "
            f"traffic; observed IKE={facts['ike_version']!r}, "
            f"Child-SA={facts['child_sa_established']!r}."
        )
    if flows.empty:
        raise ValueError("Capture contains no parseable ESP flows.")

    digest = _sha256(source_path)
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    destination = CAPTURES_DIR / (
        f"external-{traffic_type}-{digest[:12]}{source_path.suffix.casefold()}"
    )
    if destination.exists() and _sha256(destination) != digest:
        raise FileExistsError(f"Refusing to overwrite different capture: {destination}")
    if not destination.exists():
        shutil.copy2(source_path, destination)
    if _sha256(destination) != digest:
        destination.unlink(missing_ok=True)
        raise OSError("Capture hash changed while copying; registration was cancelled.")

    existing: dict[str, dict[str, object]] = {}
    if MANIFEST_PATH.is_file():
        with MANIFEST_PATH.open(encoding="utf-8") as manifest_file:
            for line_number, line in enumerate(manifest_file, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid capture manifest on line {line_number}: {exc}"
                    ) from exc
                if not isinstance(entry, dict) or not isinstance(
                    entry.get("capture_file"), str
                ):
                    raise ValueError(
                        f"Invalid capture manifest entry on line {line_number}."
                    )
                existing[entry["capture_file"]] = entry

    existing[destination.name] = {
        "capture_file": destination.name,
        "capture_sha256": digest,
        "source": provenance,
        "license": license_name,
        "is_real_capture": True,
        "traffic_type": traffic_type,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "ike_version_observed": facts["ike_version"],
        "child_sa_observed": facts["child_sa_established"],
        "esp_flow_count": len(flows),
        "attested_by_user": True,
    }
    MANIFEST_PATH.write_text(
        "".join(
            json.dumps(existing[name], sort_keys=True) + "\n"
            for name in sorted(existing)
        ),
        encoding="utf-8",
    )
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Register an independently captured, documented real IPsec PCAP "
            "for capture-grouped classifier training."
        )
    )
    parser.add_argument("pcap", type=Path, help="Input .pcap or .pcapng")
    parser.add_argument("--traffic-type", required=True, help="Verified class label")
    parser.add_argument(
        "--provenance",
        required=True,
        help="Dataset URL, experiment record, or capture source citation",
    )
    parser.add_argument(
        "--license",
        required=True,
        help="License or documented permission basis for using the capture",
    )
    parser.add_argument(
        "--attest-real-capture",
        action="store_true",
        help="Confirm this is genuinely captured, labeled, authorized traffic.",
    )
    args = parser.parse_args()
    try:
        destination = register_capture(
            args.pcap,
            args.traffic_type,
            args.provenance,
            args.license,
            attest_real_capture=args.attest_real_capture,
        )
    except (OSError, ValueError) as exc:
        print(f"Capture registration failed: {exc}", file=sys.stderr)
        return 1
    print(f"Registered verified capture: {destination}")
    print("Rebuild features and retrain with:")
    print("  python -m features.esp_features")
    print("  python -m ml.train_classifier")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
