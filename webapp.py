"""FastAPI web interface for the IPsec capture analyzer."""

from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

ROOT = Path(__file__).resolve().parent
FIXTURES_DIR = ROOT / "captures" / "fixtures"
MANIFEST_PATH = FIXTURES_DIR / "capture_manifest.jsonl"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_CAPTURE_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}
LOGGER = logging.getLogger(__name__)

app = FastAPI(
    title="IPsec Analyzer",
    description="Analyze observable IKE and ESP security evidence in packet captures.",
    docs_url=None,
    redoc_url=None,
)
app.mount(
    "/static",
    StaticFiles(directory=str(ROOT / "dashboard" / "static")),
    name="static",
)
templates = Jinja2Templates(directory=str(ROOT / "dashboard" / "templates"))


def _demo_captures() -> list[dict[str, str]]:
    entries = [
        json.loads(line)
        for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    captures = []
    for entry in entries:
        name = entry.get("capture_file")
        if (
            entry.get("source") == "strongswan-docker-testbed"
            and isinstance(name, str)
            and (FIXTURES_DIR / name).is_file()
        ):
            captures.append(
                {
                    "name": name,
                    "traffic_type": entry["traffic_type"],
                    "profile": entry["profile"],
                }
            )
    traffic_order = {"icmp": 0, "web": 1, "bulk": 2}
    return sorted(
        captures,
        key=lambda item: (traffic_order.get(item["traffic_type"], 99), item["name"]),
    )


def _analyze_capture(capture_path: Path) -> dict[str, Any]:
    from pipeline import analyze

    result = analyze(str(capture_path))
    report_path = Path(result["report_path"])
    if not report_path.is_file():
        raise RuntimeError("Capture analysis completed without producing its HTML report.")

    score = result["score_result"]
    classifier = result["classifier_result"]
    training = result["classifier_training"]
    return {
        "label": result["label"],
        "security_score": score.get("security_score", score.get("risk_score")),
        "grade": score.get("grade"),
        "findings": score.get("findings", []),
        "rule_results": score.get("rule_results", []),
        "coverage": score.get("coverage", {}),
        "ike_facts": result["ike_facts"],
        "classifier": {
            "predicted_label": classifier.get("predicted_label"),
            "confidence": classifier.get("confidence"),
            "training_status": training.get("status"),
            "note": classifier.get("note", training.get("note")),
        },
        "report_html": report_path.read_text(encoding="utf-8"),
    }


async def _analyze_upload(upload: UploadFile) -> dict[str, Any]:
    original_name = upload.filename or ""
    safe_name = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        original_name.replace("\\", "/").rsplit("/", maxsplit=1)[-1],
    )
    if not safe_name or Path(safe_name).suffix.casefold() not in {".pcap", ".pcapng"}:
        raise HTTPException(
            status_code=415,
            detail="Upload a capture file with a .pcap or .pcapng extension.",
        )

    content = bytearray()
    while chunk := await upload.read(1024 * 1024):
        content.extend(chunk)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.",
            )
    if len(content) < 4 or bytes(content[:4]) not in ALLOWED_CAPTURE_MAGICS:
        raise HTTPException(
            status_code=422,
            detail="The uploaded file does not have a recognized PCAP or PCAPNG header.",
        )

    try:
        with tempfile.TemporaryDirectory(prefix="ipsec-capture-") as temp_dir:
            capture_path = Path(temp_dir) / safe_name
            capture_path.write_bytes(content)
            return await run_in_threadpool(_analyze_capture, capture_path)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Capture analysis failed: {exc}") from exc
    except Exception:
        LOGGER.exception("Unexpected failure while analyzing uploaded capture %s", safe_name)
        raise HTTPException(
            status_code=500,
            detail="Capture analysis failed unexpectedly. Please try a valid capture or use a bundled demo.",
        ) from None
    finally:
        await upload.close()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024)},
    )


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/demo-captures")
async def demo_captures() -> dict[str, list[dict[str, str]]]:
    return {"captures": _demo_captures()}


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...)) -> JSONResponse:
    result = await _analyze_upload(file)
    return JSONResponse(result)


@app.post("/api/demo/{capture_name}")
async def analyze_demo(capture_name: str) -> JSONResponse:
    allowed_names = {item["name"] for item in _demo_captures()}
    if capture_name not in allowed_names:
        raise HTTPException(status_code=404, detail="Bundled demo capture was not found.")

    capture_path = FIXTURES_DIR / capture_name
    try:
        result = await run_in_threadpool(_analyze_capture, capture_path)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Capture analysis failed: {exc}") from exc
    except Exception:
        LOGGER.exception("Unexpected failure while analyzing demo capture %s", capture_name)
        raise HTTPException(
            status_code=500,
            detail="Demo analysis failed unexpectedly. Please try again.",
        ) from None
    return JSONResponse(result)
