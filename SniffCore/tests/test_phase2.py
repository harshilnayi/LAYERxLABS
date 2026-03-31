from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sniffcore.pipeline import analyze_capture
from sniffcore.reporting import write_reports


BASELINE = Path(__file__).parent / "fixtures" / "phase2_baseline_clean.pcap"
SUSPECT = Path(__file__).parent / "fixtures" / "phase2_suspect_lab.pcap"


def test_phase2_fixtures_exist() -> None:
    assert BASELINE.exists()
    assert SUSPECT.exists()


def test_phase2_analysis_raises_baseline_aware_findings() -> None:
    report = analyze_capture(SUSPECT, baseline_capture_path=BASELINE)

    categories = {finding["category"] for finding in report["findings"]}
    assert "arp_spoofing" in categories
    assert "rogue_dhcp_server" in categories
    assert "stp_sender_drift" in categories
    assert "baseline_drift" in categories

    comparison = report["baseline_comparison"]
    assert comparison is not None
    assert "02:20:00:00:00:77" in comparison["new_dhcp_servers"]
    assert "02:20:00:00:00:88" in comparison["new_stp_senders"]
    assert report["overview"]["baseline_used"] is True
    assert report["overview"]["severity_counts"]["high"] >= 3


def test_phase2_report_mentions_baseline(tmp_path: Path) -> None:
    report = analyze_capture(SUSPECT, baseline_capture_path=BASELINE)
    json_path, markdown_path, html_path = write_reports(report, tmp_path)

    assert json_path.exists()
    assert markdown_path.exists()
    assert html_path.exists()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["baseline_comparison"]["new_dhcp_servers"] == ["02:20:00:00:00:77"]

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "## Baseline Comparison" in markdown
    assert "02:20:00:00:00:88" in markdown
    assert "Recommended action" in markdown
    assert "Capture Analysis Dashboard" in html_path.read_text(encoding="utf-8")


def test_phase2_cli_accepts_baseline_capture(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "sniffcore",
        "--pcap",
        str(SUSPECT),
        "--baseline-pcap",
        str(BASELINE),
        "--output-dir",
        str(tmp_path),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
    assert '"baseline_used": true' in result.stdout.lower()
    assert list(tmp_path.glob("sniffcore_report_*.json"))
    assert list(tmp_path.glob("sniffcore_report_*.md"))
    assert list(tmp_path.glob("sniffcore_report_*.html"))
