from __future__ import annotations

from urllib.parse import urlparse

from .models import Finding, PageRecord


SEVERITY_SCORES = {
    "low": 30,
    "medium": 60,
    "high": 90,
}

SESSION_COOKIE_NAMES = {"session", "sessionid", "sid", "auth", "token"}


def _finding(
    *,
    category: str,
    severity: str,
    title: str,
    summary: str,
    recommendation: str,
    evidence: dict,
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        score=SEVERITY_SCORES[severity],
        title=title,
        summary=summary,
        recommendation=recommendation,
        evidence=evidence,
    )


def detect_downgrade_redirects(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        location = page.headers.get("location", "")
        if page.url.startswith("https://") and location.startswith("http://"):
            findings.append(
                _finding(
                    category="downgrade_redirect",
                    severity="high",
                    title="HTTPS page redirects to HTTP",
                    summary="A captured HTTPS page redirects the user toward an HTTP destination, creating downgrade risk.",
                    recommendation="Remove the downgrade redirect and keep the full flow on HTTPS end to end.",
                    evidence={"source_url": page.url, "location": location, "status_code": page.status_code},
                )
            )
    return findings


def detect_missing_hsts(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        if not page.url.startswith("https://"):
            continue
        if page.status_code >= 400:
            continue
        if "strict-transport-security" not in page.headers:
            findings.append(
                _finding(
                    category="missing_hsts",
                    severity="medium",
                    title="HTTPS response missing HSTS",
                    summary="An HTTPS page was served without a Strict-Transport-Security header.",
                    recommendation="Add an HSTS policy so browsers remember to stay on HTTPS for future visits.",
                    evidence={"url": page.url, "status_code": page.status_code},
                )
            )
    return findings


def detect_insecure_session_cookies(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        for cookie in page.cookies:
            cookie_name = cookie.name.lower()
            looks_sensitive = any(token in cookie_name for token in SESSION_COOKIE_NAMES)
            if looks_sensitive and not cookie.secure:
                findings.append(
                    _finding(
                        category="insecure_session_cookie",
                        severity="high",
                        title="Sensitive session cookie missing Secure flag",
                        summary="A cookie that looks session-related is present without the Secure attribute.",
                        recommendation="Mark session cookies as Secure so they are not sent over plain HTTP.",
                        evidence={"url": page.url, "cookie_name": cookie.name, "http_only": cookie.http_only},
                    )
                )
    return findings


def detect_mixed_content(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        if not page.url.startswith("https://"):
            continue
        http_resources = [resource for resource in page.resources if resource.startswith("http://")]
        if not http_resources:
            continue
        findings.append(
            _finding(
                category="mixed_content",
                severity="medium",
                title="HTTPS page loads HTTP resources",
                summary="An HTTPS page includes one or more HTTP resources, which weakens the integrity of the page.",
                recommendation="Move the dependent resources to HTTPS or remove them from the page.",
                evidence={"url": page.url, "http_resources": http_resources, "resource_count": len(http_resources)},
            )
        )
    return findings


def detect_insecure_cookie_scope(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        for cookie in page.cookies:
            if cookie.same_site is None:
                findings.append(
                    _finding(
                        category="cookie_scope",
                        severity="low",
                        title="Cookie missing SameSite policy",
                        summary="A cookie was observed without an explicit SameSite attribute.",
                        recommendation="Set SameSite deliberately so cookie cross-site behavior is a conscious choice.",
                        evidence={"url": page.url, "cookie_name": cookie.name},
                    )
                )
    return findings


def run_detectors(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    findings.extend(detect_downgrade_redirects(pages))
    findings.extend(detect_missing_hsts(pages))
    findings.extend(detect_insecure_session_cookies(pages))
    findings.extend(detect_mixed_content(pages))
    findings.extend(detect_insecure_cookie_scope(pages))
    return findings
