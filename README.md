# IPsec Analyzer

An end-to-end, local-first system for inspecting IKEv1/IKEv2/IPsec packet captures:
streaming PCAP parsing, ESP flow extraction, capture-aware traffic
classification, deterministic security findings, combined HTML reports, and a
Streamlit web app. The analyzer never decrypts IKE or ESP traffic. Missing or
encrypted facts stay unknown.

## What it does

1. Parses observable IKE negotiation facts and records parse warnings.
2. Extracts size/timing features from bounded ESP windows without decrypting
   payloads; long idle gaps split windows.
3. Rebuilds a feature dataset from captures with SHA-256-verified provenance.
   Only entries marked as real in `data/capture_manifest.jsonl` are eligible for
   automatic training; uploads and synthetic fixtures are not training data.
4. Trains/evaluates a Random Forest only when the data is sufficient. Evaluation
   keeps entire PCAP captures together in stratified cross-validation, so the
   two directions of one tunnel cannot leak across training and test folds.
   Captures being predicted are reported with their held-out (out-of-fold)
   prediction, not an in-sample score.
   Training is an explicit offline action (`python -m ml.train_classifier`);
   analyzing a capture never retrains or changes the model.
5. Applies YAML-based rules and writes JSON findings and a combined HTML report.
6. Presents the same pipeline in a local or hosted Streamlit app.

The score is a prototype rule score, not a calibrated probability or production
security audit. No full training captures or trained model are bundled;
generated demo PCAPs are explicitly synthetic. Real strongSwan testbed
collection is documented below.
Results from that controlled lab do not by themselves establish performance on
independent production VPNs.

## What it does not do

- It does not decrypt IKE_AUTH, encrypted CREATE_CHILD_SA payloads, IKEv1 Quick
  Mode, or ESP data.
- It does not infer configured PFS from ESP traffic. PFS can be observed from a
  parseable CREATE_CHILD_SA key-exchange payload; otherwise it remains unknown
  unless a sourced sidecar supplies the configured value.
- It does not claim validated classifier accuracy without a committed
  `ml/eval_report.json` backed by sufficient independent captures. No trained
  model or evaluation report is currently bundled.
- It does not treat profile metadata or synthetic captures as packet-derived
  evidence or as training data.

Three compact, hash-bound fixtures derived from a genuine strongSwan testbed run
are included in [`captures/fixtures/`](./captures/fixtures/). Each has a
manifest record with the SHA-256 of the bundled PCAP and a sidecar documenting
the configured testbed values; those sidecar values are explicitly identified
as configuration metadata, not as values decoded from encrypted payloads.
Analyze one with `python pipeline.py captures/fixtures/<capture>.pcap`.
The bundled three captures do not satisfy the independent-capture minimum for
training; no trained model or accuracy claim is shipped.

## Run locally (Windows PowerShell)

Python 3.11+ is recommended:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m streamlit run dashboard\app.py
```

The web app lets you analyze a PCAP from `captures\` or upload one. To run the
same end-to-end analysis from the command line:

```powershell
python pipeline.py captures\your_capture.pcap
```

Each analysis writes a unique HTML report, a per-run findings JSON and IKE facts.
It does not train, rewrite, or promote a classifier. PDF export is enabled by
default; set `IPSEC_ANALYZER_PDF=0` to disable it. If WeasyPrint cannot render,
HTML analysis still succeeds and the export error is reported.
On Windows, WeasyPrint also requires its native Pango/Cairo libraries; use a
supported Linux environment for PDF rendering if those libraries are absent.

The sample capture is a compact real testbed fixture:

```powershell
python -m pipeline captures\fixtures\ipsec_medium-cbc-tunnel-ikev2_pfs-on_ipv4_icmp-run01.pcap --fail-under 0
```

## Collect genuine labeled IPsec training captures

The repository contains a Docker Compose testbed with six selectable
strongSwan profiles spanning IKEv1/IKEv2, AES-GCM/CBC and weak 3DES, main and
aggressive exchange modes, and PFS enabled/disabled. Each profile generates
ICMP, HTTP and bulk `iperf3` traffic. Docker Desktop is not a supported capture
host unless its Linux kernel provides XFRM; use a native Linux VM/host with
XFRM support, Docker Engine and Compose v2.

```powershell
python tools\collect_real_dataset.py --profile medium-cbc-tunnel-ikev2 --repetitions 3 --duration-seconds 10
python -m features.esp_features
python -m ml.train_classifier
```

Omit `--profile` to collect all six profiles; provide a name to collect just
one. Captures are refused if their output names already exist. The collector
validates IKE and ESP traffic and writes SHA-256-bound records with profile
metadata to `data/capture_manifest.jsonl`. Training requires genuine captures
whose hashes and labels match this manifest. At least three independent
captures per traffic class are required for capture-grouped cross-validation.

### Profiles

| Profile | IKE | ESP | PFS | Expected grade |
|---|---|---|---|---|
| `strong-gcm-tunnel-ikev2` | IKEv2, AES-GCM, MODP2048 | AES-GCM-256 | On | A |
| `medium-cbc-tunnel-ikev2` | IKEv2, AES-CBC, MODP2048 | AES-CBC-256/SHA2-256 | On | A |
| `weak-3des-tunnel-ikev2` | IKEv2, 3DES/SHA-1, MODP1024 | 3DES/SHA-1 | On | F |
| `ikev1-main-aes` | IKEv1 Main Mode, AES-256 | AES-CBC-256/SHA2-256 | On | D |
| `ikev1-aggressive-weak` | IKEv1 Aggressive, DES/MD5 | 3DES/MD5 | On | F |
| `pfs-off-tunnel-ikev2` | IKEv2, AES-GCM, MODP2048 | AES-GCM-256 | Off | B |

Grades describe this repository's configured prototype scoring policy, not a
certification or a NIST compliance determination. Profile configuration is
recorded in a per-capture JSON sidecar and labelled as sidecar-sourced data.

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

The committed fixtures are three captures (one per traffic class), so they are
explicitly insufficient to train a validated model. Add more independently
captured runs and profiles before making an accuracy claim. Never register
synthetic or unlabeled captures as real.

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

### Training and evaluation

After collecting enough independently captured, labeled traffic, rebuild the
feature dataset and train offline:

```powershell
python -m features.esp_features
python -m ml.train_classifier
```

Read `ml/eval_report.json` before using a model. `status` must be `trained`;
`cv_accuracy_mean` is capture-grouped cross-validation (both directions of a
capture stay in one fold), and `per_class` and `confusion_matrix` show where
errors occur. `leave_one_profile_out.mean_accuracy` measures generalization to
profiles withheld entirely from training; it is unavailable until there are
enough captures across multiple profiles. `baseline_majority_accuracy` is a
simple reference, not a quality threshold. If the report says
`insufficient_data`, no accuracy result or validated model is available.

The bundled fixtures currently contain only one independent capture per
traffic class, so they do not satisfy the training minimum. Analyze captures
without retraining; training is always an explicit offline command.

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

## Pitch and demo materials

- [Technical brief](./docs/TECHNICAL_BRIEF.md) summarizes the problem, system,
  evidence, and open validation work.
- [Demo script](./docs/DEMO_SCRIPT.md) distinguishes the reproducible bundled
  capture walkthrough from profile-configuration scoring. A real weak-profile
  PCAP demo still requires Linux/XFRM collection.

## Run tests

```powershell
python -m pip install -r requirements-dev.txt
ruff check .
python -m pytest -q --cov
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

## Scoring and observability

The YAML policy is [`scoring/rules.yaml`](./scoring/rules.yaml). Each rule is
reported as `PASS`, `FAIL`, or `NOT OBSERVABLE`; unknown inputs do not lower or
increase the score. Reports include observed-rule coverage and whether a value
came from packet parsing or an explicitly sourced sidecar. The score and grade
are a documented prototype policy and should be reviewed against current
standards and organizational requirements.

## Sidecar format

Place a JSON file beside a capture using the name `<capture>.pcap.json`. A
non-empty `source` is required; only validated fields are applied, and
capture-derived values take precedence:

```json
{
  "source": "strongSwan testbed profile medium-cbc-tunnel-ikev2",
  "mode": "tunnel",
  "pfs": true,
  "esp_encryption": "AES-CBC-256",
  "esp_integrity": "HMAC-SHA2-256-128",
  "sa_lifetime_seconds": 1800
}
```

Sidecars describe externally sourced/configured facts. They are not evidence
that encrypted negotiation payloads were decrypted.

## Repository layout

```text
dashboard/       Streamlit UI
captures/fixtures/ compact SHA-256-bound real capture fixtures and sidecars
features/        Streaming ESP flow features
ipsec_parser/    IKE parsing and sidecar validation
ml/              Offline capture-grouped classifier training/evaluation
report/           HTML template and optional PDF export
scoring/          YAML findings policy and score/grade helpers
testbed/profiles/ six strongSwan profile configurations
tests/            Parser, scoring, provenance, and pipeline tests
tools/            Collection and fixture utilities
```

## License

This project is released under the [MIT License](./LICENSE).
