#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
REPETITIONS="${1:-3}"
DURATION_SECONDS="${2:-10}"
VENV_DIR="$ROOT/.venv-real-validation"
CAPTURES_DIR="$ROOT/captures"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Run this script inside your Kali Linux VM." >&2
  exit 1
fi
if [[ ! "$REPETITIONS" =~ ^[0-9]+$ ]] || (( REPETITIONS < 3 )); then
  echo "Repetitions must be an integer of at least 3." >&2
  exit 2
fi
if [[ ! "$DURATION_SECONDS" =~ ^[0-9]+$ ]] || (( DURATION_SECONDS < 3 )); then
  echo "Bulk traffic duration must be an integer of at least 3 seconds." >&2
  exit 2
fi
if [[ ! -f "$ROOT/requirements.txt" || ! -f "$ROOT/testbed/docker-compose.yml" ]]; then
  echo "Run this script from a copy of the complete project repository." >&2
  exit 1
fi

for traffic in icmp web bulk; do
  for ((run = 1; run <= REPETITIONS; run++)); do
    capture="$CAPTURES_DIR/tunnel_aes256cbc_pfs-on_ipv4_${traffic}-run$(printf '%02d' "$run").pcap"
    if [[ -e "$capture" ]]; then
      echo "Refusing to overwrite existing capture: $capture" >&2
      echo "Move that capture elsewhere before starting a fresh validation run." >&2
      exit 1
    fi
  done
done

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required to install and start Docker." >&2
  exit 1
fi

retry() {
  local attempt
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    fi
    if (( attempt < 3 )); then
      echo "Command failed; retrying ($attempt/3): $*" >&2
      sleep 10
    fi
  done
  return 1
}

echo "[1/7] Installing Docker, Compose, and Python environment tools..."
retry sudo apt-get update
retry sudo apt-get install -y docker.io docker-compose python3-venv python3-pip

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker installation did not provide the docker command." >&2
  exit 1
fi
if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl enable --now docker
else
  sudo service docker start
fi

REAL_DOCKER="$(command -v docker)"
sudo -v
WRAPPER_DIR="$(mktemp -d)"
KEEPALIVE_PID=""
COLLECTION_IN_PROGRESS=0
cleanup() {
  if [[ -n "$KEEPALIVE_PID" ]]; then
    kill "$KEEPALIVE_PID" 2>/dev/null || true
  fi
  if (( COLLECTION_IN_PROGRESS )); then
    for traffic in icmp web bulk; do
      for ((run = 1; run <= REPETITIONS; run++)); do
        partial="$CAPTURES_DIR/tunnel_aes256cbc_pfs-on_ipv4_${traffic}-run$(printf '%02d' "$run").pcap"
        rm -f -- "$partial"
      done
    done
  fi
  rm -rf -- "$WRAPPER_DIR"
}
trap cleanup EXIT

cat > "$WRAPPER_DIR/docker" <<'DOCKER_WRAPPER'
#!/bin/sh
exec sudo -n "$IPSEC_REAL_DOCKER" "$@"
DOCKER_WRAPPER
chmod +x "$WRAPPER_DIR/docker"
export IPSEC_REAL_DOCKER="$REAL_DOCKER"
export PATH="$WRAPPER_DIR:$PATH"
(while sleep 45; do sudo -n -v 2>/dev/null || exit; done) &
KEEPALIVE_PID=$!

echo "[2/7] Checking Docker daemon and Compose..."
docker info >/dev/null
docker compose version >/dev/null 2>&1 || docker-compose version >/dev/null

echo "[3/7] Preparing isolated Python environment and installing project requirements..."
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  python3 -m venv "$VENV_DIR"
fi
retry "$VENV_DIR/bin/python" -m pip install --upgrade pip
retry "$VENV_DIR/bin/python" -m pip install -r "$ROOT/requirements.txt"

echo "[4/7] Running project tests..."
cd "$ROOT"
"$VENV_DIR/bin/python" -m pytest -q

echo "[5/7] Capturing genuine strongSwan IKEv2/ESP traffic..."
COLLECTION_IN_PROGRESS=1
"$VENV_DIR/bin/python" "$ROOT/tools/collect_real_dataset.py" \
  --repetitions "$REPETITIONS" \
  --duration-seconds "$DURATION_SECONDS"
COLLECTION_IN_PROGRESS=0

echo "[6/7] Verifying captures, building features, and evaluating the classifier..."
"$VENV_DIR/bin/python" - "$ROOT" "$REPETITIONS" <<'PY'
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
repetitions = int(sys.argv[2])
captures = root / "captures"
manifest = root / "data" / "capture_manifest.jsonl"
entries = [
    json.loads(line)
    for line in manifest.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
expected = repetitions * 3
entries = [
    entry for entry in entries
    if entry.get("source") == "strongswan-docker-testbed"
    and entry.get("capture_file", "").startswith("tunnel_aes256cbc_pfs-on_ipv4_")
]
if len(entries) != expected:
    raise SystemExit(f"Expected {expected} new testbed manifest entries; found {len(entries)}.")
counts = Counter(entry["traffic_type"] for entry in entries)
if counts != Counter({"icmp": repetitions, "web": repetitions, "bulk": repetitions}):
    raise SystemExit(f"Unexpected traffic class counts: {dict(counts)}")
for entry in entries:
    path = captures / entry["capture_file"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != entry["capture_sha256"]:
        raise SystemExit(f"SHA-256 mismatch for {path.name}")
print(f"Verified {len(entries)} capture hashes and traffic labels: {dict(counts)}")
PY
"$VENV_DIR/bin/python" -m features.esp_features
"$VENV_DIR/bin/python" -m ml.train_classifier
"$VENV_DIR/bin/python" - "$ROOT" <<'PY'
import json
import sys
from pathlib import Path

report = Path(sys.argv[1]) / "ml" / "eval_report.json"
result = json.loads(report.read_text(encoding="utf-8"))
if result.get("status") != "trained":
    raise SystemExit(f"Classifier was not trained: {result.get('note')}")
print(
    f"Classifier evaluated: {result['n_samples']} flows, "
    f"{result['n_classes']} classes, "
    f"capture-grouped CV accuracy {result['cv_accuracy_mean']:.3f}"
)
PY

echo "[7/7] Running full analysis and producing an HTML report..."
FIRST_CAPTURE="$CAPTURES_DIR/tunnel_aes256cbc_pfs-on_ipv4_icmp-run01.pcap"
"$VENV_DIR/bin/python" "$ROOT/pipeline.py" "$FIRST_CAPTURE"

echo
echo "REAL TESTBED VALIDATION COMPLETED"
echo "Captures: $CAPTURES_DIR"
echo "Manifest: $ROOT/data/capture_manifest.jsonl"
echo "Model evaluation: $ROOT/ml/eval_report.json"
echo "HTML reports: $ROOT/reports"
echo "This validates real traffic from the local strongSwan testbed, not an independent production VPN."
