"""Show the scoring policy on profile metadata, not on packet captures."""

from __future__ import annotations

import json
from pathlib import Path

from scoring.scorer import score_capture

ROOT = Path(__file__).resolve().parents[1]
PROFILE_NAMES = ("strong-gcm-tunnel-ikev2", "weak-3des-tunnel-ikev2")


def main() -> None:
    print("Configuration-only scoring demo; these are not PCAP analysis results.")
    for profile_name in PROFILE_NAMES:
        metadata_path = ROOT / "testbed" / "profiles" / profile_name / "metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        facts = {
            "ike_version": metadata["ike_version"],
            "ike_exchange_mode": metadata.get("ike_exchange_mode"),
            "pfs_enabled": metadata["pfs"],
            "esp_encryption_algorithm": metadata["esp_encryption"],
            "esp_integrity_algorithm": metadata["esp_integrity"],
            "dh_group": metadata["dh_group"],
            "sa_lifetime_seconds": metadata["sa_lifetime_seconds"],
            "fact_sources": {
                key: f"sidecar: configured profile {profile_name}"
                for key in (
                    "ike_version",
                    "ike_exchange_mode",
                    "pfs_enabled",
                    "esp_encryption_algorithm",
                    "esp_integrity_algorithm",
                    "dh_group",
                    "sa_lifetime_seconds",
                )
            },
        }
        result = score_capture(facts)
        if result["grade"] != metadata["expected_grade"]:
            raise RuntimeError(
                f"{profile_name}: expected {metadata['expected_grade']}, "
                f"got {result['grade']}"
            )
        finding_ids = ", ".join(finding["id"] for finding in result["findings"])
        print(
            f"{profile_name}: {result['security_score']}/100 "
            f"grade {result['grade']}; findings: {finding_ids or 'none'}"
        )


if __name__ == "__main__":
    main()
