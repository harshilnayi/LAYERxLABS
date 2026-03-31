from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sniffcore.pipeline import analyze_capture
from sniffcore.reporting import write_reports


FIXTURE = Path(__file__).parent / "fixtures" / "sample_phase1_lab.pcap"


def test_phase1_fixture_exists() -> None:
    assert FIXTURE.exists()


def test_analysis_extracts_summary_and_findings() -> None:
    report = analyze_capture(FIXTURE)

    assert report["overview"]["total_frames"] == 11
    assert report["overview"]["broadcast_frames"] == 8
    assert report["overview"]["findings_count"] >= 3
    assert report["overview"]["risk_score"] >= 60
    assert report["protocols"]["ARP"] == 9
    assert report["protocols"]["TCP"] == 2

    categories = {finding["category"] for finding in report["findings"]}
    assert "duplicate_ip_mapping" in categories
    assert "mac_churn" in categories
    assert "broadcast_noise" in categories


def test_report_writer_outputs_json_and_markdown(tmp_path: Path) -> None:
    report = analyze_capture(FIXTURE)
    json_path, markdown_path, html_path = write_reports(report, tmp_path)

    assert json_path.exists()
    assert markdown_path.exists()
    assert html_path.exists()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["overview"]["total_frames"] == 11
    assert "SniffCore Analysis Report" in markdown_path.read_text(encoding="utf-8")
    assert "Capture Analysis Dashboard" in html_path.read_text(encoding="utf-8")


def test_cli_runs_end_to_end(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "sniffcore",
        "--pcap",
        str(FIXTURE),
        "--output-dir",
        str(tmp_path),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
    assert '"total_frames": 11' in result.stdout
    assert list(tmp_path.glob("sniffcore_report_*.json"))
    assert list(tmp_path.glob("sniffcore_report_*.md"))
    assert list(tmp_path.glob("sniffcore_report_*.html"))
