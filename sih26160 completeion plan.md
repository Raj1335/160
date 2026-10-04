# SIH26160 IPsec Analyzer: Production-Grade Completion Plan

Scope: finishing the software only. Nothing here covers idea submission, slides or pitch.

Basis: a read-through of `sih26160-ipsec-analyzer.zip` (parser, features, ML, scoring, report, dashboard, tools, testbed, tests). The tests were **not executed** because the review sandbox had no network to install `scapy` and `pytest`. Run `pytest -q` locally to confirm the current state before starting.

---

## 1. Where the project stands

### Keep (already good)
- Unknown values stay `None`; nothing is guessed.
- Captures carry SHA-256 provenance in a manifest; synthetic captures are blocked from training.
- Cross-validation is grouped by capture, so the two directions of one tunnel cannot leak between train and test.
- A real strongSwan Docker testbed and a collector script exist.
- Scoring rules are in YAML.

### Known defects (fix first)

| # | Where | Problem | Effect |
|---|---|---|---|
| D1 | `parser/ike_parser.py` `_INTEGRITY` | IANA IDs are wrong. Correct IKEv2 values: 1=HMAC-MD5-96, 2=HMAC-SHA1-96, 5=AES-XCBC-96, 8=AES-CMAC-96, 12=HMAC-SHA2-256-128, 13=HMAC-SHA2-384-192, 14=HMAC-SHA2-512-256. The table has 5=SHA2-256, 6=SHA2-384, 7=SHA2-512, 12=XCBC, 13=CMAC. | A real SHA2-256 tunnel (ID 12) is reported as AES-XCBC. The `weak_integrity` rule is unreliable. |
| D2 | `_ENCRYPTION` | 11 is mapped to `3DES` but is NULL. 1 is DES_IV64 and DES (2) is missing. CTR (13), CCM (14-16) and ChaCha20-Poly1305 (28) are missing. | NULL encryption is misreported; modern suites appear as "Encryption transform N". |
| D3 | `_DH` | Missing groups 17, 18, 22-30, 32 and others. | Unrecognised groups are reported as unknown. |
| D4 | `scoring/scorer.py` `long_sa_lifetime` | Fires whenever the value is `None`. IKEv2 never carries lifetimes on the wire, so `sa_lifetime_seconds` is always `None`. | Every capture loses 5 points and gets a meaningless finding. The existing test asserts this. |
| D5 | `no_auth_detected` rule | The parser only ever sets `ike_sa_established` to `True` or `None`, never `False`. | This critical rule can never fire. |
| D6 | `parse_ike()` | One flat dict, first-seen-wins via `setdefault`. | Rekeys, multiple IKE SAs, multiple child SAs and multiple tunnels in one capture are merged or dropped. |
| D7 | Protocol coverage | IKEv1 is detected but not parsed. AH (protocol 51), IKEv2 fragments and IKE-over-TCP are ignored. ESP over IPv6 with extension headers is probably missed. | Large parts of an IPsec analyzer's scope are absent. |
| D8 | `pipeline.analyze()` | Rebuilds the whole dataset and retrains the model on every analysis. Writes global files, can delete `model.pkl`, names output files from the user's filename. | Slow, unsafe under concurrency, filename collisions. |
| D9 | `predict_traffic_type()` | Calls `joblib.load` once per flow. | Slow. Unpickling a model file is also a code-execution risk if the file is ever untrusted. |
| D10 | Performance | Up to three scapy passes plus a hash per capture. | Large captures will crawl. |
| D11 | ML features | `packet_count`, `bytes_total`, `flow_duration_seconds` depend on how long the capture ran. Each SPI is one direction and is classified alone. | The model can learn your capture script instead of the traffic. |
| D12 | Repo hygiene | `dsd.zip` is a 3.8 MB `.wav` unrelated to the project. `requirements.txt` has no version pins. `captures/*.pcap` globs ignore `.pcapng`, which the UI accepts. `ipsec.secrets` PSK is committed (acceptable for a lab only). | Clutter and breakage before any review. |
| D13 | Naming | `risk_score` means 100 = best. | Confusing for users. |

---

## 2. Phased plan

### Phase 0: Hygiene (about half a day)
- [ ] Remove `dsd.zip` and purge it from git history (`git filter-repo`). Check with `git ls-files`.
- [ ] Pin dependencies (`pip-compile` or `uv lock`) and pin the Python version.
- [ ] Rename `risk_score` to `security_score` (or invert it so higher means riskier). Update report, UI and tests.
- [ ] Turn the project into an installable package (`pyproject.toml`); rename the `parser/` package to something unambiguous such as `ipsec_analyzer/`.
- [ ] Fix pcap/pcapng globbing everywhere (`*.pcap` and `*.pcapng`).
- [ ] Add `ruff` and `mypy` configuration and make the codebase pass.

**Done when:** a clean clone installs with one command and lint/type checks pass.

### Phase 1: Rewrite the parser around a session model (core work)
- [ ] Replace the flat dict with typed models (dataclasses or pydantic): `Capture`, `IkeSa`, `ChildSa`, `EspFlow`, `Finding`, `Evidence`.
- [ ] Every fact carries `observed | inferred | unknown` and the packet numbers it came from.
- [ ] Generate IANA registries (encryption, PRF, integrity, DH, ESN, auth method, notify types) from the official CSVs instead of typing them by hand. Add a test that checks known IDs.
- [ ] Group packets by IKE SPI pair. Track rekeys, child SAs, DPD and retransmissions.
- [ ] Reassemble IKEv2 fragments (RFC 7383).
- [ ] Parse IKEv1: main mode, aggressive mode, quick mode, proposal attributes, vendor IDs.
- [ ] Add AH parsing. Handle IPv6 extension headers and NAT-T keepalives/non-ESP markers correctly.
- [ ] ESP sequence-number analysis: gaps, reordering, wraparound, duplicates. This is observable without decryption and is the honest basis for any replay-related finding.
- [ ] Use cleartext notifies (`NO_PROPOSAL_CHOSEN`, `AUTHENTICATION_FAILED`, `INVALID_KE_PAYLOAD`, etc.) to set `ike_sa_established=False` legitimately.
- [ ] Single-pass reading (`dpkt`, or scapy only as a fallback) that yields IKE, ESP and flow data together. Stream; do not load whole captures in memory.
- [ ] Fuzz test (`hypothesis` or `atheris`): truncated, zero-length, oversize-length and random packets never crash the run.

**Done when:** a multi-tunnel, rekeying capture produces the correct number of IKE SAs and child SAs, each with its own algorithms and evidence.

### Phase 2: Rules engine and ground truth
- [ ] Make rules fully data-driven: operators (`in`, `not_in`, `lt`, `gt`, `absent`), no special-casing by rule id in code.
- [ ] Three-state result per rule: **pass / fail / not observable**. "Not observable" never deducts points; list it in its own report section.
- [ ] Each rule has: id, severity, rationale, standards reference (RFC 8221 / RFC 8247 for algorithms, NIST SP 800-77r1), remediation text and example config snippet. Verify references against the current documents.
- [ ] Minimum rule coverage: DES/3DES/NULL, AES-CBC without strong integrity, MD5/SHA-1, DH groups under 2048-bit, missing PFS where observable, IKEv1 aggressive mode with PSK, deprecated IKE versions, no encryption, no integrity, anonymous/weak authentication where visible, NAT-T exposure, ESP sequence anomalies.
- [ ] Documented scoring: severity weights, hard caps, per-finding breakdown.
- [ ] **Testbed matrix generator**: vary `ike=` / `esp=` in the strongSwan configs to produce real captures for each rule (3DES, MODP1024, SHA1, no PFS, IKEv1 aggressive, and so on). One passing and one failing capture per rule.
- [ ] Golden-file tests that run every matrix capture and assert the exact expected findings.

**Done when:** every rule has a real positive and a real negative capture and CI asserts both.

### Phase 3: Make the ML real
- [ ] Define the task: traffic category inside the tunnel. Add anomaly detection only if required, and validate it with injected anomalies.
- [ ] Widen the data: VoIP/RTP, video, SSH, browsing, file transfer, DNS, bulk. Vary cipher suite, NAT-T on/off, IPv4/IPv6, MTU, and use `tc netem` for latency and loss. Aim for 20 or more captures per class.
- [ ] Re-engineer features: fixed windows (5 s or N packets), both directions combined, size histograms, up/down ratio, inter-arrival quantiles, burstiness. **Drop** absolute duration, packet count and byte totals.
- [ ] Honest evaluation: nested grouped CV, per-class precision/recall/F1, macro-F1, confusion matrix, probability calibration, an "unknown" output below a confidence threshold.
- [ ] Out-of-distribution test: train on strongSwan captures, test on a different implementation (for example Libreswan).
- [ ] Train offline only, never inside `analyze()`. Save a versioned artifact with metadata (data hash, feature list, library versions, metrics). Load once at startup using a safe format (`skops` or ONNX) rather than raw pickle.
- [ ] Add explainability (feature importance or SHAP) to the report.

**Done when:** reported metrics come from held-out captures, include a second implementation, and the UI shows confidence plus the model version.

### Phase 4: Service architecture
- [ ] Split into core library, API (FastAPI) and worker (RQ or arq). Streamlit becomes a thin client, or is replaced.
- [ ] Jobs: UUID directory, status, progress, cancellation, versioned JSON result schema, stored in SQLite or Postgres.
- [ ] Upload hardening: magic-byte check, size cap, per-job timeout and memory limit, parser run in a separate low-privilege process or container.
- [ ] Authentication, rate limiting, audit log, retention and deletion endpoints.
- [ ] OpenAPI docs, consistent error schema, WebSocket or SSE progress.
- [ ] If Streamlit is kept for time reasons: still do job isolation, no training in the request path, per-job output directories and cached results.

**Done when:** two simultaneous uploads cannot interfere, and a hostile file fails cleanly.

### Phase 5: Reports and UI
- [ ] Executive summary, per-session detail, SA timeline, findings sorted by severity with evidence (packet numbers, timestamps) and remediation.
- [ ] "Not observable" and "inferred" are visibly distinct from "observed".
- [ ] Export HTML, JSON and PDF (WeasyPrint). Optional machine-readable export (SARIF or STIX).
- [ ] Empty, loading and error states; large captures use paginated or virtualised tables.
- [ ] Remove "prototype" wording only after the Phase 7 checks pass.

### Phase 6: Tests and CI
- [ ] Unit tests for parsers, registries and rules; integration test pcap to report; API contract tests.
- [ ] Small real testbed pcaps committed as fixtures (mind size and licensing).
- [ ] Benchmark with a stated budget (for example a 500 MB capture within a set time and memory).
- [ ] GitHub Actions: `ruff`, `mypy`, `pytest --cov` (80% or more on the core), `pip-audit`, `gitleaks`, Docker build.

### Phase 7: Packaging, ops and docs
- [ ] Dockerfile for the app; compose file with the testbed under a separate profile; non-root user; health check.
- [ ] Configuration through environment variables with documented defaults (`.env.example`).
- [ ] Structured JSON logs and metrics.
- [ ] Docs: README (architecture, limits), rules catalogue, model card, threat model, short runbook.
- [ ] Note: `render.yaml` on the free tier has an ephemeral filesystem and sleeps when idle. Fine for a demo, not production.

---

## 3. Definition of done

- [ ] One command brings up the whole system from a clean machine.
- [ ] Every rule has a real positive and a real negative capture, asserted in CI.
- [ ] Multi-tunnel and rekeying captures are modelled correctly.
- [ ] A malformed or hostile pcap fails gracefully and does not take the service down.
- [ ] ML metrics are from held-out captures, including a second implementation, and are shown with the model version.
- [ ] Nothing in the UI or report claims more than the packets support.
- [ ] CI is green; dependencies are pinned and scanned; no secrets in the repo or history.

---



## 4. Honest limits to keep in the product

- IKE_AUTH and later IKEv2 payloads are encrypted. Authentication method, child SA details and PFS are often not observable from a capture; report them as unknown.
- Traffic classification is inference from metadata, not decryption, and its accuracy depends on how close the data is to the training conditions.
- The scoring policy is a configurable baseline; review it against current standards and the organisation's policy before relying on it.
