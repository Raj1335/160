from pathlib import Path

from streamlit.testing.v1 import AppTest

from dashboard.app import _available_captures

ROOT = Path(__file__).resolve().parents[1]


def test_bundled_fixtures_are_available_in_dashboard():
    captures = _available_captures()

    assert ROOT / "captures" / "fixtures" / (
        "ipsec_medium-cbc-tunnel-ikev2_pfs-on_ipv4_icmp-run01.pcap"
    ) in captures


def test_dashboard_shows_demo_and_waits_for_explicit_analysis():
    app = AppTest.from_file(str(ROOT / "dashboard" / "app.py")).run(timeout=30)

    assert not app.exception
    assert any(button.label == "Analyze capture" for button in app.button)
    assert not any("Analysis:" in item.value for item in app.subheader)
