from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from stripsec.pipeline import analyze_capture
from stripsec.reporting import write_reports


FIXTURE = Path(__file__).parent / "fixtures" / "sample_transport_capture.json"


def test_fixture_exists() -> None:
    assert FIXTURE.exists()


def test_analysis_raises_expected_findings() -> None:
    report = analyze_capture(FIXTURE)

    assert report["overview"]["pages_analyzed"] == 3
    assert report["overview"]["findings_count"] >= 5
    assert report["overview"]["risk_level"] in {"medium", "high"}

    categories = {finding["category"] for finding in report["findings"]}
    assert "downgrade_redirect" in categories
    assert "missing_hsts" in categories
    assert "insecure_session_cookie" in categories
    assert "mixed_content" in categories


def test_report_writer_outputs_all_formats(tmp_path: Path) -> None:
    report = analyze_capture(FIXTURE)
    json_path, markdown_path, html_path = write_reports(report, tmp_path)

    assert json_path.exists()
    assert markdown_path.exists()
    assert html_path.exists()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["overview"]["pages_analyzed"] == 3
    assert "StripSec Analysis Report" in markdown_path.read_text(encoding="utf-8")
    assert "Transport Security Dashboard" in html_path.read_text(encoding="utf-8")


def test_cli_runs_end_to_end(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "stripsec",
        "--input",
        str(FIXTURE),
        "--output-dir",
        str(tmp_path),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
    assert '"pages_analyzed": 3' in result.stdout
    assert list(tmp_path.glob("stripsec_report_*.json"))
    assert list(tmp_path.glob("stripsec_report_*.md"))
    assert list(tmp_path.glob("stripsec_report_*.html"))
