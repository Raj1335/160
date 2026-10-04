# Free web deployment and SIH demo checklist

## Website architecture

The judge-facing site is a custom HTML/CSS/JavaScript frontend served by
FastAPI. FastAPI provides the page, a health endpoint, bundled-capture demo
analysis, and a size-limited PCAP/PCAPNG upload API. Analysis stays in the
existing Python pipeline; there is no third-party AI service or API key.

## Deploy to Render

Render's free Python web service is configured in [`../render.yaml`](../render.yaml).
To create it:

1. Push the project to GitHub.
2. Sign in to [render.com](https://render.com), choose **New → Blueprint**, and
   connect the `Raj1335/160` repository.
3. Confirm Render finds the `sih26160-ipsec-analyzer` service in `render.yaml`
   and deploy it.
4. Wait for the first dependency install and deploy to finish.
5. Open the service's public `onrender.com` URL. `/healthz` should return
   `{"status":"ok"}` and `/` should show the custom analyzer.
6. Run the bundled ICMP demo capture and confirm the score, rule coverage,
   findings, and technical report download.

The service uses:

```text
uvicorn webapp:app --host 0.0.0.0 --port $PORT --workers 1
```

One worker avoids duplicating the analyzer and scikit-learn memory footprint on
the small free instance. PDF rendering is disabled on the hosted service; HTML
report download remains available. Uploads are limited to 25 MiB and checked
for both extension and PCAP/PCAPNG header. Cloud dependencies are pinned in the
root `requirements.txt`.

## Free-tier cold starts

Render's [free-instance documentation](https://render.com/docs/free) says free
web services spin down after 15 minutes without inbound traffic; waking one
typically takes about a minute. Free hosting therefore **cannot promise an
instant response if judges first visit after the app has gone idle**. The
service does not use keep-alive traffic to bypass the host's sleep policy.

If a no-cost host is required:

- Deploy and test the public URL at least a day ahead.
- Shortly before judging, open the URL, wait for it to load, run the bundled
  demo once, and keep the working app page open.
- Rehearse the same capture locally as a fallback; do not rely on event-hall
  Wi-Fi.
- Be candid with judges that a free host may cold-start after inactivity.

If instant availability after arbitrary inactivity is mandatory, an always-on
paid service is required.

## Local fallback

```powershell
python -m pip install -r requirements-dev.txt
python -m uvicorn webapp:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Both the site and analysis run locally, without
needing event network access. Press `Ctrl+C` to stop the server.

## Privacy and current demo boundaries

Render's filesystem is ephemeral. Uploaded captures and generated reports are
temporary and can disappear after a restart or redeploy. Do not upload
confidential traffic captures to a public service.

The bundled demo captures are compact, hash-bound derivatives of the
documented strongSwan testbed. There is one capture per traffic class, too few
to train a validated classifier. The bundled capture's A grade is a result
under the prototype scoring policy, not a certification. The weak-profile
demonstration scores configured profile metadata, not a weak PCAP; label it
accordingly.
