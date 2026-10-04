# IPsec Analyzer

An end-to-end, local-first system for inspecting IKEv2/IPsec packet captures:
streaming PCAP parsing, ESP flow extraction, capture-aware traffic
classification, deterministic security findings, combined HTML reports, and a
Streamlit web app. The analyzer never decrypts IKE or ESP traffic. Missing or
encrypted facts stay unknown.

## What it does

1. Parses observable IKEv2 negotiation facts and records parse warnings.
2. Extracts size/timing features per ESP SPI without decrypting payloads.
3. Rebuilds a feature dataset from captures with SHA-256-verified provenance.
   Only entries marked as real in `data/capture_manifest.jsonl` are eligible for
   automatic training; uploads and synthetic fixtures are not training data.
4. Trains/evaluates a Random Forest only when the data is sufficient. Evaluation
   keeps entire PCAP captures together in stratified cross-validation, so the
   two directions of one tunnel cannot leak across training and test folds.
   Captures being predicted are reported with their held-out (out-of-fold)
   prediction, not an in-sample score.
5. Applies YAML-based rules and writes JSON findings and a combined HTML report.
6. Presents the same pipeline in a local or hosted Streamlit app.

The score is a prototype rule score, not a calibrated probability or production
security audit. No full training captures or trained model are bundled;
generated demo PCAPs are explicitly synthetic. Real strongSwan testbed
collection is documented below.
Results from that controlled lab do not by themselves establish performance on
independent production VPNs.

Three compact, hash-bound fixtures derived from a genuine strongSwan testbed run
are included in [`captures/fixtures/`](./captures/fixtures/). Each has a
manifest record with the SHA-256 of the bundled PCAP and a sidecar documenting
the configured testbed values; those sidecar values are explicitly identified
as configuration metadata, not as values decoded from encrypted payloads.
Analyze one with `python pipeline.py captures/fixtures/<capture>.pcap`.

## Run locally (Windows PowerShell)

Python 3.11+ is recommended:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run dashboard\app.py
```

The web app lets you analyze a PCAP from `captures\` or upload one. To run the
same end-to-end analysis from the command line:

```powershell
python pipeline.py captures\your_capture.pcap
```

Outputs include `data\ike_facts\`, `data\flow_features.csv`,
`data\findings\`, `ml\eval_report.json`, and `reports\report_<capture>.html`.
Analysis output and source captures are local and are not committed by default.

## Collect genuine labeled IPsec training captures

The repository contains a Docker Compose testbed using two real strongSwan
IKEv2 endpoints. It negotiates AES-CBC-256 with HMAC-SHA2-256 IPsec SAs, captures the actual IKE/ESP
packets, and generates three distinct kinds of traffic inside the tunnel:
ICMP, HTTP, and bulk `iperf3`. These are genuine captures of a working local
VPN testbed, not packets fabricated by Scapy. The data-collection machine needs
Docker Desktop with Linux containers and kernel IPsec/XFRM support; Docker
builds the endpoint image on first use.

```powershell
python tools\collect_real_dataset.py --repetitions 3 --duration-seconds 10
python -m features.esp_features
python -m ml.train_classifier
```

The collection command validates that each PCAP contains IKEv2 and ESP before
writing its SHA-256 and traffic label to `data\capture_manifest.jsonl`. Three
independent captures per traffic class are required for capture-grouped
cross-validation. The training pipeline excludes captures whose hashes do not
match the manifest. It never promotes an uploaded or synthetic capture to
training data based on its filename alone.

On Kali Linux, the following command automates Docker/Compose setup, Python
dependency installation, testbed capture collection, capture/manifest checks,
model evaluation, and one end-to-end HTML report:

```bash
bash tools/run_kali_real_validation.sh
```

The first run needs internet access and `sudo` for package installation and
Docker. It defaults to three captures per traffic class and refuses to
overwrite captures from a previous run. Optional arguments set repetitions
(minimum 3) and bulk-transfer duration in seconds (minimum 3).

A local Kali/strongSwan validation run completed with nine captures (three per
traffic class), 18 ESP flows, and three-fold capture-grouped evaluation. The
observed 100% accuracy is based only on this small, single-testbed dataset; it
validates the collection and analysis path, not expected accuracy on independent
VPN implementations or production networks. Captures and model artifacts from
that run are retained locally rather than bundled here. You may also place
independently collected PCAPs in `captures\`, but they remain ineligible for
automatic training until their provenance and verified traffic labels are
registered in the manifest. Do not register synthetic or unlabeled captures as
real.

For an independently sourced, licensed real IKEv2/ESP capture, register it
explicitly with a verified class label and a provenance citation:

```powershell
python tools\register_capture.py path\to\real_capture.pcap `
  --traffic-type web `
  --provenance "https://example.org/dataset or lab experiment record" `
  --license "Dataset license or written permission" `
  --attest-real-capture
```

The command validates observable IKEv2 and ESP traffic, copies the capture into
`captures\`, hashes it, and records the supplied provenance and label in the
manifest. The attestation flag is an explicit human responsibility, not an
automated authenticity guarantee. Only register captures that are genuinely
captured, correctly labeled, and authorized for this use.

### Public IPsec research data considered

The public [IPSec-VPN-Classification repository](https://github.com/vverky/IPSec-VPN-Classification)
contains `ftp_true.csv`, `im_true.csv`, and `web_true.csv` packet-level ESP
records and declares an MIT license. These are useful research references, but
they are not raw PCAPs and do not retain source-capture IDs. Inspection found
only two SPIs per class and one continuous sequence per class file; treating
individual packets as independent cross-validation samples would leak the same
tunnel/session into training and evaluation. I therefore did **not** import
them as independent training captures or present metrics from them. Confirm
the data rights and obtain the original per-capture PCAPs/boundaries before
using that source for validated training. The strongSwan collector above
produces capture-separated data in the feature format this project evaluates.

For parser/report/UI development only, a structurally plausible synthetic
fixture can be created with:

```powershell
python tools\generate_demo_capture.py
python pipeline.py captures\demo_aesgcm256_pfs-on_ipv4_synthetic.pcap
```

**This fixture is synthetic and is never accepted by the real-data training
path.**

## Run tests

```powershell
python -m pytest -q
```

## Deploy the web app for free on Render

The included [`render.yaml`](./render.yaml) defines a free Render web service.
In Render, create a **New Blueprint Instance** from this repository and deploy
the `sih26160-ipsec-analyzer` service. The service binds Streamlit to Render's
`$PORT` and exposes Streamlit's health endpoint. For manual setup, use:

- Build command: `pip install -r requirements.txt`
- Start command:
  `streamlit run dashboard/app.py --server.address 0.0.0.0 --server.port $PORT --server.headless true`
- Health check path: `/_stcore/health`

Render's free web instances can sleep when idle and have an ephemeral
filesystem. The hosted app can analyze uploaded PCAPs, but uploaded data,
generated reports, and models trained at runtime are not durable across
restarts/redeploys. For a hosted, pre-trained classifier, collect and evaluate
the real dataset locally, then deploy only data/model artifacts you are
authorized to publish; do not commit confidential network captures. Durable
multi-user datasets require persistent storage or an external object store,
which is intentionally not assumed or required for local operation.

## Limitations

- Encrypted IKE_AUTH payloads do not reveal authentication method or all Child
  SA details. PFS remains unknown unless a parseable CREATE_CHILD_SA exchange is
  present, even when the lab manifest records the configured value.
- IKE negotiation and ESP visibility depend on what the capture point observes.
- Traffic labels are ground truth only when generated by the documented
  testbed or otherwise independently verified.
- The scoring policy cites NIST SP 800-77 Rev. 1 and RFC 8221 as references;
  review current guidance and organizational policy before relying on findings.
