from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .detectors import run_detectors
from .ingest import load_capture


def _summarize_severity(findings: list[dict]) -> tuple[dict[str, int], int, str]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding["severity"]] += 1

    risk_score = min(100, counts["high"] * 30 + counts["medium"] * 15 + counts["low"] * 5)
    if risk_score >= 70:
        risk_level = "high"
    elif risk_score >= 35:
        risk_level = "medium"
    else:
        risk_level = "low"

    return counts, risk_score, risk_level


def analyze_capture(capture_path: str | Path) -> dict:
    capture = load_capture(capture_path)
    pages = capture["pages"]
    findings = [finding.to_dict() for finding in run_detectors(pages)]
    severity_counts, risk_score, risk_level = _summarize_severity(findings)

    domains = sorted({urlparse(page.url).netloc for page in pages})
    https_pages = sum(1 for page in pages if page.url.startswith("https://"))
    http_pages = sum(1 for page in pages if page.url.startswith("http://"))

    return {
        "capture": {
            "name": capture["capture_name"],
            "source": str(Path(capture_path).resolve()),
        },
        "overview": {
            "pages_analyzed": len(pages),
            "domains_seen": len(domains),
            "https_pages": https_pages,
            "http_pages": http_pages,
            "findings_count": len(findings),
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "risk_level": risk_level,
        },
        "domains": domains,
        "pages": [page.to_dict() for page in pages],
        "findings": findings,
    }
