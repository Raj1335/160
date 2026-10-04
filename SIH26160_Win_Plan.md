# SIH26160 — Win Plan (Post-Real-Data Finishing Guide)

Assumes: `SIH26160_RealData_Automation_Spec.md` has run successfully — you have ≥3 real captures per traffic class, `ml/eval_report.json` shows `"status": "trained"`, and at least one real HTML report exists. This document is everything left to turn that into a submission that can actually win, not just pass.

---

## 1. What "winning" actually requires, beyond "it works"

A working prototype gets you through screening. Winning at SIH requires judges to walk away believing three specific things, and everything below is organized around proving each one:

1. **This is a real, understood security problem** — not a toy demo.
2. **The team understands the limits of their own AI claim** — judges specifically probe "is this really AI or just Wireshark" on security PSes; teams that oversell get torn apart.
3. **This is differentiated from what 50+ other teams building the same PS will submit.**

Everything in this doc maps to one of those three.

---

## 2. Expand the dataset breadth (if time remains — priority order matters)

You already have the core 4-config matrix from the spec. If time allows after real data collection succeeds, add these in this exact priority order (stop whenever time runs out — each one adds standalone value):

1. **Transport mode capture** (if not already done) — lets your demo show mode detection working on both tunnel AND transport, directly matching PS §c's explicit ask to "identify Tunnel Mode / Transport Mode."
2. **A second deliberately-weak config**: DH Group 1 (768-bit) specifically, separate from your existing weak CBC/SHA1 config — DH Group 1/2 is explicitly named in real-world IPsec vulnerability advisories (Logjam-class attacks); having your scorer flag this by name during a live demo is a strong, specific, defensible moment.
3. **IPv6 capture** — even just one config repeated over IPv6. The PS explicitly lists "IPv4 and IPv6 communication" as a requirement; even partial IPv6 coverage closes a visible gap competitors may also skip, but having it gives you an answer if asked.
4. **A 4th traffic type** (your spec currently covers icmp/bulk/web — add a 4th like a simulated VoIP pattern via `iperf3 -u` UDP mode with small packet sizes at a regular interval) — improves classifier class balance and gives a better confusion matrix to show.

**Do not chase full matrix completeness.** A judge asking "did you test AES-CBC with DH group 14 over IPv6 with PFS disabled" is not a real risk — nobody expects full coverage from a student prototype. What they're actually checking is whether you understand *why* each dimension matters, which the next section covers.

---

## 3. The technical defense document — write this, it's your biggest lever

Create `TECHNICAL_DEFENSE.md` in the repo. This is not for the judges to read proactively — it's your own prep document so that when they ask hard questions, your team answers crisply instead of improvising. Structure it as Q&A:

**Q: "Is this actually AI, or is it just parsing packets?"**
A: Be exact. IKE field extraction (cipher, mode, DH group, PFS) is deterministic protocol parsing — no ML, and we don't claim it's AI. The genuine ML component is ESP traffic-type classification, because ESP payload is encrypted and offers no fields to parse — only statistical side-channel features (packet size/timing patterns) remain, which is a legitimate applied-ML problem with real academic precedent (cite: encrypted traffic classification literature exists broadly — e.g. work on VPN traffic fingerprinting via packet size/timing). We're explicit in our own report about which parts are deterministic vs. ML, because conflating them would be dishonest and judges can tell.

**Q: "What's your classifier's real accuracy, and do you trust it?"**
A: State your actual cross-validated number (from `eval_report.json`) plainly, compare it to the majority-class baseline (also in that file) to show real lift, and name the known limitation: the model is trained on your own lab's traffic-generator "fingerprint" (synthetic iperf3/curl patterns), so it may not generalize to real-world app traffic (real WhatsApp, real video codecs) without further data collection. This honesty is a feature, not a weakness — overclaiming a 99% accuracy on a 12-sample dataset is instantly disqualifying to any judge who understands ML.

**Q: "Why should an analyst trust your risk score over just reading the IKE log themselves?"**
A: The score doesn't replace the analyst's judgment — it triages. For N tunnels on an enterprise gateway, manually reading every IKE negotiation log takes meaningful analyst time; our tool makes the triage decision ("these 3 are fine, these 2 need review") in seconds, with every finding traceable back to the exact field that triggered it (show the technical report's field-level detail as proof it's not a black box).

**Q: "What happens with AH-based deployments, or non-PSK auth (certificates)?"**
A: Explicitly out of scope — PS marks AH optional, and we prioritized ESP + PSK to cover the more common deployment and prove the pipeline end-to-end rather than spread thin. State this as a conscious scoping decision (it is, because you made it this way), not an oversight.

**Q: "Could a sophisticated attacker evade your traffic classifier?"**
A: Yes — padding, traffic shaping, or protocol obfuscation (e.g., traffic morphing) could defeat size/timing-based classification. This is a known, published limitation of all side-channel traffic classification research, not unique to our implementation. Our tool is a defensive triage aid, not an adversarial-robust detection system — a legitimate scope boundary to state plainly if asked.

**Q: "Why strongSwan/your own lab instead of a real enterprise capture?"**
A: Ethical and practical: capturing real production/third-party traffic without authorization is both illegal and outside what we could responsibly do as students. Our own fully-controlled testbed gives us ground-truth labels, which real captured traffic never would (we'd be guessing at what cipher was actually used) — this is methodologically the correct choice, not a limitation we're hiding.

Write 2-3 more anticipated questions specific to your actual demo once you've run it once end-to-end and know where it's shaky.

---

## 4. Strengthen the report output for judge-facing polish

Your existing HTML report (from the pipeline spec) is functionally complete. Before the final submission, do these specific, low-effort upgrades:

1. **Add a one-paragraph "Methodology" box** at the top of the report citing NIST SP 800-77 Rev.1 and RFC 8221 explicitly by name (not just "industry standards") — judges who dig in will check this, and having it citable in the artifact itself (not just verbally) is stronger.
2. **Add the classifier's confusion matrix as an image** (matplotlib, export as PNG, embed via `<img>` tag or base64 inline) rather than just a JSON blob — visual evidence reads as more rigorous than a table of numbers.
3. **Side-by-side comparison mode**: if you have both a weak and strong config captured, generate a single combined comparison report (or just open two report tabs side by side in the dashboard) — this is literally Section 36 of the original blueprint's demo design, and it's the single most persuasive visual you can show: same tool, two configs, dramatically different scores, both correctly explained.

---

## 5. The demo script — write and rehearse this verbatim

Time-box: SIH internal-round demos are usually 5-10 minutes. Script exactly this flow, rehearse it twice before presenting:

1. **(30s) Problem framing:** "IPsec secures a huge amount of enterprise/government traffic, but misconfiguration is common and manual review doesn't scale. We built a tool that automates the triage."
2. **(60s) Architecture in one breath:** capture → deterministic IKE parsing (show this is NOT ML, be upfront) → ML traffic classification on ESP metadata (show this IS the ML, be upfront) → rule-based scoring against NIST 800-77 → automated report.
3. **(90s) Live demo, weak config:** upload/select the deliberately weak capture (DH Group 1 or CBC+SHA1). Show the dashboard flag it — walk through the technical report's exact field (e.g. "DH Group 1 detected — vulnerable to precomputation attacks") and the resulting low risk score.
4. **(90s) Live demo, strong config:** switch to the AES-256-GCM/PFS-on capture. Show the score jump, and the threat matrix come up clean. This contrast is your best single moment — don't rush it.
5. **(60s) The AI component, honestly:** show the classifier's prediction + confidence score on one flow, state the real accuracy number from your eval report, and proactively say the one-sentence limitation ("trained on our own lab traffic, real-world generalization needs more data") before anyone asks — pre-empting the hard question is much stronger than being caught by it.
6. **(30s) Close:** "Working prototype, real strongSwan testbed, dataset and trained classifier, full report generation — everything in the PS's deliverable list is here." Point at the GitHub repo link.

**Rehearse the weak-config walkthrough until you can name the exact finding without looking it up** — this is the moment judges remember.

---

## 6. Deliverables checklist — map directly to PS's "Expected Solution/Deliverables"

Go through this literally before submitting, check each one has a corresponding file/link ready:

- [ ] **Working software prototype** → GitHub repo link (Raj1335/160), confirm `README.md` run instructions actually work on a clean checkout (test this once if time allows — a broken README during judging is a bad look)
- [ ] **AI classification engine** → `ml/model.pkl` + `ml/eval_report.json` committed or clearly described as reproducible via the documented command
- [ ] **Interactive dashboard** → Streamlit app, either the Render-hosted link (check it's awake — free Render instances sleep when idle, ping it 10 minutes before your demo slot) or a local screen-share fallback if Render is asleep/unreliable
- [ ] **Security assessment report** → at least 2 real generated HTML reports (one weak config, one strong config) saved and linked
- [ ] **Demonstration video** → record using the Section 5 script, 5-8 minutes, screen capture with narration; upload to YouTube unlisted or wherever SIH wants it submitted
- [ ] **Technical documentation** → `README.md` + `PROJECT_IMPLEMENTATION_REPORT.md` already exist; add `TECHNICAL_DEFENSE.md` from Section 3; consider a one-page architecture diagram image (even a simple draw.io/hand-drawn box diagram of capture→parser→classifier→scorer→report→dashboard) — visual documentation reads better to non-technical evaluators than prose alone
- [ ] **Dataset used for training/testing** → `data/capture_manifest.jsonl` + the real `.pcap` files — decide now whether to commit the actual pcaps to the repo (they're small, probably fine) or describe the collection process and provide them separately if judges ask; don't leave this ambiguous at submission time

---

## 7. Final pre-submission sanity pass (do this once, the night before / morning of)

1. Fresh clone the repo to a clean folder, follow `README.md` exactly as written, confirm it actually works from zero — this catches "works on my machine" gaps.
2. Open the Render-hosted dashboard link cold (not from a cached tab) and confirm it loads and a real capture can be analyzed through it.
3. Re-read `eval_report.json` one more time — confirm `status: "trained"` is still what's committed (not accidentally overwritten by a later synthetic-only test run).
4. Watch your own demo video once, full-length, like a judge would — note anything confusing and fix the script/narration if needed, not the code, this close to deadline.
5. Have one teammate (or yourself, cold) try to break the dashboard with an edge case (upload a non-pcap file, a 0-byte file) — confirm it fails gracefully with a message, not a raw Python traceback on screen. This was explicitly designed for in the pipeline spec (Stage 1/2 error handling) — verify it actually holds.

---

## 8. What NOT to do with remaining time

- Don't add new features (AH support, new ciphers, a chatbot, anything not already scoped) this close to submission — every new line of code is a new way for the live demo to break.
- Don't try to inflate the classifier's reported accuracy by cherry-picking a favorable fold or re-running training repeatedly until a better number appears — a judge who asks "how many times did you run this" and gets an honest "once, this is the real cross-validated number" answer is in a much stronger position than one who can't answer that cleanly.
- Don't over-polish the dashboard UI at the expense of rehearsing the verbal demo — judges forgive a plain-looking Streamlit app; they don't forgive a team that can't explain their own risk score calculation when asked.
