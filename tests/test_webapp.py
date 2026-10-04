from pathlib import Path

from fastapi.testclient import TestClient

import webapp

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_NAME = "ipsec_medium-cbc-tunnel-ikev2_pfs-on_ipv4_icmp-run01.pcap"


def test_homepage_serves_custom_web_app_and_stylesheet():
    client = TestClient(webapp.app)

    response = client.get("/")

    assert response.status_code == 200
    assert "See what your" in response.text
    assert "Analyze capture" in response.text
    assert "Streamlit" not in response.text
    stylesheet = client.get("/static/app.css")
    assert stylesheet.status_code == 200
    assert ".hero" in stylesheet.text


def test_health_and_bundled_demo_catalog():
    client = TestClient(webapp.app)

    assert client.get("/healthz").json() == {"status": "ok"}
    captures = client.get("/api/demo-captures").json()["captures"]
    assert len(captures) == 3
    assert any(capture["name"] == FIXTURE_NAME for capture in captures)


def test_demo_endpoint_analyzes_real_fixture_and_returns_report(monkeypatch):
    monkeypatch.setenv("IPSEC_ANALYZER_PDF", "0")
    client = TestClient(webapp.app)

    response = client.post(f"/api/demo/{FIXTURE_NAME}")

    assert response.status_code == 200
    result = response.json()
    assert result["security_score"] == 100
    assert result["grade"] == "A"
    assert result["findings"] == []
    assert result["coverage"]["observed"] == 6
    assert result["classifier"]["training_status"] == "insufficient_data"
    assert "<!doctype html>" in result["report_html"].lower()


def test_upload_endpoint_analyzes_capture_in_temporary_storage(monkeypatch):
    monkeypatch.setenv("IPSEC_ANALYZER_PDF", "0")
    client = TestClient(webapp.app)
    fixture = ROOT / "captures" / "fixtures" / FIXTURE_NAME

    with fixture.open("rb") as capture:
        response = client.post(
            "/api/analyze",
            files={"file": (FIXTURE_NAME, capture, "application/vnd.tcpdump.pcap")},
        )

    assert response.status_code == 200
    result = response.json()
    assert result["label"] == Path(FIXTURE_NAME).stem
    assert result["security_score"] == 100
    assert result["report_html"]


def test_upload_rejects_unknown_extension_and_invalid_capture_header():
    client = TestClient(webapp.app)

    wrong_extension = client.post(
        "/api/analyze",
        files={"file": ("capture.txt", b"not a capture", "text/plain")},
    )
    invalid_header = client.post(
        "/api/analyze",
        files={"file": ("capture.pcap", b"not a capture", "application/octet-stream")},
    )

    assert wrong_extension.status_code == 415
    assert invalid_header.status_code == 422


def test_upload_enforces_configured_size_limit(monkeypatch):
    monkeypatch.setattr(webapp, "MAX_UPLOAD_BYTES", 8)
    client = TestClient(webapp.app)

    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "capture.pcap",
                b"\xd4\xc3\xb2\xa1extra",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 413


def test_demo_endpoint_does_not_accept_arbitrary_paths():
    client = TestClient(webapp.app)

    response = client.post("/api/demo/../../requirements.txt")

    assert response.status_code == 404
