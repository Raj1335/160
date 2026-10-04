# IPsec Analyzer — Technical Brief

## Problem

An IPsec packet capture can show the IKE exchanges and ESP traffic visible at a
capture point, but it does not give an operator a safe, complete view of every
negotiated or configured security property. Encrypted IKE payloads hide
authentication and Child SA details, and ESP payloads are not readable without
keys. At the same time, packet sizes and timing can still support bounded flow
analysis. The analyzer makes those boundaries explicit instead of treating
unknown values as facts.

## Solution

This project is a local-first Python application for examining IKEv1/IKEv2 and
ESP packet captures. It produces:

- Parsed IKE facts and warnings, while leaving encrypted values unknown.
- Windowed ESP packet-size and timing features, with long idle gaps splitting
  windows.
- A deterministic, YAML-configured security score, grade, findings, and
  observed-rule coverage.
- A combined HTML report and an optional PDF export.
- An offline traffic-classifier training/evaluation path that is separate from
  capture analysis and bound to verified capture provenance.

The analyzer is a prototype decision aid, not a probability estimate, security
certification, or substitute for an organization's policy review.

## Architecture and evidence

The pipeline streams packets through the IKE parser and ESP feature extractor,
applies the scoring policy, and writes unique per-run facts, findings, and
reports. Rule results distinguish `PASS`, `FAIL`, and `NOT OBSERVABLE`; absent
evidence does not earn a pass or incur a penalty. Reports also attribute values
to packet parsing or a sourced sidecar.

Six strongSwan testbed profiles cover IKEv1/IKEv2, AES-GCM and AES-CBC,
deprecated 3DES/DES configurations, IKEv1 Main and Aggressive modes, and PFS
enabled/disabled. The repository includes three compact captures derived from
a genuine strongSwan Docker testbed run. Their packet order and timestamps are
preserved, packets are truncated to 128 bytes, and a manifest binds each
fixture to its SHA-256 digest and source capture. The adjacent sidecars identify
configured profile values; they are not claims that encrypted fields were
decoded.

The bundled capture demonstrates a score of **100 / A**, with 6 of 9 rules
observable and no findings under the current prototype policy. This result is
not a security certification. The bundled set contains one capture per traffic
class and is insufficient for classifier training. There is no trained model
or validated accuracy claim in the repository.

## Training and validation

Training is an explicit offline operation:

```text
python -m features.esp_features
python -m ml.train_classifier
```

`ml/eval_report.json` reports capture-grouped cross-validation, per-class
performance, and—when enough profiles are represented—leave-one-profile-out
evaluation. The latter tests whether a model generalizes to an unseen profile.
Insufficient data is reported as such; packet windows from the same capture
are not treated as independent examples.

Automated CI runs Ruff and pytest on Python 3.11 and 3.12 and exercises a
synthetic end-to-end pipeline. A Linux validation script collects genuine
strongSwan traffic using Docker Compose and XFRM, verifies manifest hashes,
then attempts training and reporting. It has not been run from this Windows
workspace. The committed fixtures and tests are reproducible here, but real
Linux/XFRM collection and native PDF rendering remain environment-dependent.

## Limitations and next work

- No IKE_AUTH, encrypted CREATE_CHILD_SA, Quick Mode, or ESP payload decryption
  is performed. PFS is taken from a parseable CREATE_CHILD_SA key exchange when
  observable; otherwise a sourced sidecar can report configured PFS, or it
  remains unknown.
- The compact fixtures do not constitute a multi-profile training dataset.
  Collect more independent captures per class and profile before claiming
  classifier performance.
- A real weak-profile PCAP has not been bundled. Profile configuration scores
  can test the scoring policy, but must not be presented as capture results.
- Docker Desktop is not assumed to provide Linux XFRM. Real collection requires
  a Linux host or VM with XFRM and Docker Compose.
- PDF output depends on WeasyPrint and native Pango/Cairo/GObject libraries.

## Quick start

Install the pinned development dependencies, then analyze the bundled fixture:

```text
python -m pip install -r requirements-dev.txt
python -m pipeline captures/fixtures/ipsec_medium-cbc-tunnel-ikev2_pfs-on_ipv4_icmp-run01.pcap --fail-under 0
```

See the [README](../README.md) for profile details, setup instructions, and the
full test and collection commands.
