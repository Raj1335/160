# Three-minute demo script

## Before the demo

Use a clean checkout with `requirements-dev.txt` installed. Confirm the
bundled fixture exists and run `ruff check .` and `python -m pytest -q`.
Optional PDF output needs Linux Pango/Cairo/GObject libraries; do not depend on
PDF rendering for a Windows-hosted demo.

## Walkthrough

### 0:00–0:25 — Set the boundary

Say: “This is a passive analyzer. It does not decrypt IKE_AUTH, encrypted
CREATE_CHILD_SA payloads, Quick Mode, or ESP. Unknown facts stay unknown, and
the report labels whether an observation came from the packets or a sourced
sidecar.”

### 0:25–1:20 — Analyze a real-derived fixture

Run:

```text
python -m pipeline captures/fixtures/ipsec_medium-cbc-tunnel-ikev2_pfs-on_ipv4_icmp-run01.pcap --fail-under 0
```

Show the `100 / A` score, empty findings list, and coverage of 6 observed rules
out of 9. Point to the `sidecar:` sources for configured ESP algorithms and
PFS, and to the parse warning explaining why PFS is not packet-observable in
this particular fixture. Explain that the fixture is derived from a genuine
strongSwan testbed capture and is SHA-256-bound in
`captures/fixtures/capture_manifest.jsonl`.

### 1:20–2:05 — Contrast strong and weak profile policy

Run:

```text
python -m tools.demo_profile_scoring
```

This prints the strong profile as grade A and the weak 3DES profile as grade F
with their configured-profile findings. Be explicit: this is a scoring-policy
demonstration on profile metadata, **not** analysis of two captured PCAPs. The
repository does not currently contain a weak-profile capture.

### 2:05–2:35 — Explain training honesty

Point to the pipeline output: classifier status is `insufficient_data`; no
prediction or accuracy claim is made. The bundled fixtures provide one
independent capture per class, below the training minimum. Show the Linux
collection command in the README as the next step for generating a proper
multi-profile evaluation set.

### 2:35–3:00 — Close

Summarize the differentiators: evidence provenance, explicit observability
coverage, immutable per-run outputs, and capture-grouped evaluation. Offer the
HTML report and point to the scoring policy and test suite.

## Not yet demo-ready

A true weak-PCAP-versus-strong-PCAP walkthrough, a trained-model accuracy
comparison, and a guaranteed PDF export require Linux/XFRM collection,
sufficient independent captures, and working native PDF libraries. Do not
claim those results until the generated artifacts have been reviewed and
committed. An AICTE idea-round slide PDF is not included: this checkout has no
official slide template, and no current official submission window for this
problem statement was confirmed during this review.
