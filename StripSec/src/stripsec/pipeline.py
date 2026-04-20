from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .detectors import run_detectors, summarize_redirect_downgrades
from .ingest import load_capture
from .models import PageRecord


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


def _host(url: str) -> str:
    return urlparse(url).netloc


def _all_domains(pages: list[PageRecord]) -> list[str]:
    domains = {_host(page.url) for page in pages if _host(page.url)}
    for page in pages:
        domains.update(_host(resource) for resource in page.resources if _host(resource))
    return sorted(domains)


def _protection_summary(pages: list[PageRecord]) -> dict:
    https_pages = [page for page in pages if page.url.startswith("https://") and page.status_code < 400]
    session_cookies = [
        cookie
        for page in pages
        for cookie in page.cookies
        if any(token in cookie.name.lower() for token in {"session", "sid", "auth", "token", "jwt"})
    ]

    return {
        "https_pages_with_hsts": sum(1 for page in https_pages if "strict-transport-security" in page.headers),
        "https_pages_with_csp": sum(1 for page in https_pages if "content-security-policy" in page.headers),
        "https_pages_with_referrer_policy": sum(1 for page in https_pages if "referrer-policy" in page.headers),
        "session_cookies_seen": len(session_cookies),
        "secure_session_cookies": sum(1 for cookie in session_cookies if cookie.secure),
        "http_submission_pages": sum(
            1 for page in pages if page.url.startswith("http://") and page.method in {"POST", "PUT", "PATCH"}
        ),
    }


def analyze_capture(capture_path: str | Path) -> dict:
    capture = load_capture(capture_path)
    pages = capture["pages"]
    findings = [finding.to_dict() for finding in run_detectors(pages)]
    severity_counts, risk_score, risk_level = _summarize_severity(findings)

    domains = _all_domains(pages)
    https_pages = sum(1 for page in pages if page.url.startswith("https://"))
    http_pages = sum(1 for page in pages if page.url.startswith("http://"))
    redirect_downgrades = summarize_redirect_downgrades(pages)

    return {
        "capture": {
            "name": capture["capture_name"],
            "source": str(Path(capture_path).resolve()),
            "format": capture["format"],
        },
        "overview": {
            "pages_analyzed": len(pages),
            "domains_seen": len(domains),
            "https_pages": https_pages,
            "http_pages": http_pages,
            "redirect_downgrades": len(redirect_downgrades),
            "findings_count": len(findings),
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "risk_level": risk_level,
        },
        "protection_summary": _protection_summary(pages),
        "redirect_downgrades": redirect_downgrades,
        "domains": domains,
        "pages": [page.to_dict() for page in pages],
        "findings": findings,
    }
