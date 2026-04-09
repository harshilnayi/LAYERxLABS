from __future__ import annotations

from pathlib import Path

from sniffcore.pipeline import analyze_capture


QUIET = Path(__file__).parent / "fixtures" / "phase1_quiet_lab.pcap"
CHATTY = Path(__file__).parent / "fixtures" / "phase1_chatty_but_ok.pcap"
GROWTH_BASELINE = Path(__file__).parent / "fixtures" / "phase2_growth_baseline.pcap"
GROWTH_CAPTURE = Path(__file__).parent / "fixtures" / "phase2_growth_capture.pcap"


def test_variety_fixtures_exist() -> None:
    assert QUIET.exists()
    assert CHATTY.exists()
    assert GROWTH_BASELINE.exists()
    assert GROWTH_CAPTURE.exists()


def test_quiet_capture_stays_clean() -> None:
    report = analyze_capture(QUIET)

    assert report["overview"]["total_frames"] == 5
    assert report["overview"]["findings_count"] == 0
    assert report["overview"]["risk_level"] == "low"


def test_chatty_but_normal_capture_does_not_raise_noise_findings() -> None:
    report = analyze_capture(CHATTY)
    categories = {finding["category"] for finding in report["findings"]}

    assert report["overview"]["total_frames"] == 10
    assert report["overview"]["broadcast_frames"] == 3
    assert "broadcast_noise" not in categories
    assert "mac_churn" not in categories
    assert report["overview"]["findings_count"] == 0


def test_growth_capture_does_not_trigger_baseline_drift_on_small_expansion() -> None:
    report = analyze_capture(GROWTH_CAPTURE, baseline_capture_path=GROWTH_BASELINE)
    categories = {finding["category"] for finding in report["findings"]}

    assert report["baseline_comparison"] is not None
    assert sorted(report["baseline_comparison"]["new_source_macs"]) == [
        "02:30:00:00:00:40",
        "02:30:00:00:00:41",
    ]
    assert "baseline_drift" not in categories
    assert "rogue_dhcp_server" not in categories
    assert "stp_sender_drift" not in categories
    assert report["overview"]["findings_count"] == 0
