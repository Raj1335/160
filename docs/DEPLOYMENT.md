# Free web deployment and SIH demo checklist

## Recommendation

Deploy the Streamlit application to
[Streamlit Community Cloud](https://share.streamlit.io). It is the most direct
free fit for this repository: the UI is Streamlit, the analysis backend is
Python, and the public GitHub repository already contains the pinned
dependencies and bundled demo captures.

The dashboard loads the fixture list without importing the classifier,
feature-building stack, or capture pipeline. Selecting a file does not start
analysis by itself; the visitor explicitly clicks **Analyze capture**. This
keeps the initial landing page light and avoids surprise analysis on page
loads. Analysis imports what it needs and generates the report on demand.

## Streamlit Community Cloud setup

1. Confirm the latest project changes are pushed to `main`.
2. Sign in to [Streamlit Community Cloud](https://share.streamlit.io) with
   GitHub and authorize the repository.
3. Create an app using:
   - Repository: `Raj1335/160`
   - Branch: `main`
   - Main file path: `dashboard/app.py`
   - Python: `3.11`
   - App URL: choose an available short, recognizable name.
4. Deploy. Cloud uses the root `requirements.txt`; no API keys or secrets are
   required for the current demo.
5. When the build completes, open the public app URL in a private/incognito
   browser window. Select the bundled ICMP fixture, run analysis, inspect the
   A grade and coverage, then test the HTML report download.
6. Save the URL, deploy logs, and a screenshot of the working results for
   judges and teammates.

The app may warn that PDF export is unavailable if the host lacks native
WeasyPrint/Pango/Cairo libraries. HTML analysis and download are the primary
demo path; a PDF warning should not be mistaken for a failed capture analysis.

## What “free and fast” can and cannot mean

Community Cloud is free, but a free shared host is not an SLA. Streamlit
documents that apps without traffic for 12 hours go to sleep; the sleeping
page lets a visitor request wake-up. Builds usually take a few minutes, and
capacity/platform limits can change. Opening the app shortly before an event
reduces the chance of a cold start during the presentation, but does not
guarantee that it remains warm. Do not use third-party keep-alive pings to try
to defeat a host's sleep policy.

Render remains configured in [`../render.yaml`](../render.yaml), but its
documented free-service behavior is especially unsuitable for an unannounced
judge visit: a service that has received no inbound traffic for 15 minutes
spins down, and waking it typically takes about a minute. See
[Render's free instance limits](https://render.com/docs/free).

If the requirement is a guaranteed immediate response after arbitrary
inactivity, a free shared service cannot promise that. Arrange an always-on
paid host or use the local fallback below. Avoid promising “instant” service
based solely on a successful warm test.

## Before judging

- At least one day ahead: deploy, open the public URL, test it from a browser
  that is not signed into the deployment account, and confirm analysis/report
  download.
- Just before the session: open the public URL, wait for the app to finish
  loading, select the bundled ICMP fixture, and run the analysis. Keep the
  working app page available for the presentation.
- Rehearse the separate profile-policy demonstration with
  `python -m tools.demo_profile_scoring`. This is configuration scoring, not
  analysis of weak and strong capture files.
- Keep a local fallback ready: install `requirements-dev.txt`, run
  `streamlit run dashboard/app.py`, and verify the same fixture on the laptop.
  Do not depend on event-hall Wi-Fi for this fallback.
- Do not upload confidential captures to the public hosted demo. The service
  has an ephemeral filesystem, and uploaded PCAPs/reports are not durable.

## Evidence and available demo

The bundled genuine-testbed-derived captures are under `captures/fixtures/`.
They are compact provenance fixtures, not a trained dataset. The available
web walkthrough uses the medium AES-CBC configuration and reports the
prototype-policy A grade; it does not demonstrate real captured weak-profile
traffic. A weak-vs-strong PCAP comparison still requires collecting a weak
profile on Linux/XFRM and validating the resulting captures. Do not represent
the profile-metadata demo as packet analysis.
