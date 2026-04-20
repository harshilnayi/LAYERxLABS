from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from .models import Finding, PageRecord


SEVERITY_SCORES = {
    "low": 30,
    "medium": 60,
    "high": 90,
}

SESSION_COOKIE_NAMES = {"session", "sessionid", "sid", "auth", "token", "jwt", "refresh", "access"}
SENSITIVE_FIELD_NAMES = {"password", "passwd", "pwd", "token", "auth", "session", "otp", "secret"}


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


def _is_https(url: str) -> bool:
    return url.lower().startswith("https://")


def _is_http(url: str) -> bool:
    return url.lower().startswith("http://")


def _host(url: str) -> str:
    return urlparse(url).netloc


def _looks_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in SESSION_COOKIE_NAMES | SENSITIVE_FIELD_NAMES)


def _hsts_max_age(header_value: str) -> int | None:
    for part in header_value.split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "max-age" and value.isdigit():
            return int(value)
    return None


def _sensitive_query_keys(url: str) -> list[str]:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    return sorted(key for key in query if _looks_sensitive(key))


def _page_has_sensitive_submission(page: PageRecord) -> bool:
    if any(_looks_sensitive(field) for field in page.form_fields):
        return True
    if page.post_body:
        lowered = page.post_body.lower()
        return any(token in lowered for token in SENSITIVE_FIELD_NAMES)
    return False


def detect_downgrade_redirects(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        location = page.headers.get("location", "")
        if _is_https(page.url) and location.startswith("http://"):
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


def detect_http_sensitive_submission(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        if not _is_http(page.url):
            continue
        if page.method not in {"POST", "PUT", "PATCH"}:
            continue
        if not _page_has_sensitive_submission(page):
            continue
        findings.append(
            _finding(
                category="sensitive_submission_over_http",
                severity="high",
                title="Sensitive form data submitted over HTTP",
                summary="A captured HTTP request appears to submit sensitive form fields without transport encryption.",
                recommendation="Move this endpoint to HTTPS and reject sensitive submissions over plain HTTP.",
                evidence={"url": page.url, "method": page.method, "form_fields": page.form_fields},
            )
        )
    return findings


def detect_query_secrets(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        sensitive_keys = _sensitive_query_keys(page.url)
        if not sensitive_keys:
            continue
        severity = "high" if _is_http(page.url) else "medium"
        findings.append(
            _finding(
                category="sensitive_query_parameter",
                severity=severity,
                title="Sensitive value appears in the URL query string",
                summary="A captured URL contains query parameters that look sensitive and may leak through logs, history, or referrers.",
                recommendation="Move sensitive values out of URLs and into properly protected request bodies or headers.",
                evidence={"url": page.url, "sensitive_query_keys": sensitive_keys},
            )
        )
    return findings


def detect_missing_hsts(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        if not _is_https(page.url):
            continue
        if page.status_code >= 400:
            continue
        hsts = page.headers.get("strict-transport-security")
        if not hsts:
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
            continue

        max_age = _hsts_max_age(hsts)
        if max_age is not None and max_age < 2_592_000:
            findings.append(
                _finding(
                    category="weak_hsts",
                    severity="low",
                    title="HSTS max-age is short",
                    summary="The response includes HSTS, but the max-age is short enough that protection expires quickly.",
                    recommendation="Use a longer HSTS max-age after confirming the site is ready to stay on HTTPS.",
                    evidence={"url": page.url, "max_age": max_age, "header": hsts},
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

            if looks_sensitive and not cookie.http_only:
                findings.append(
                    _finding(
                        category="session_cookie_script_access",
                        severity="medium",
                        title="Sensitive session cookie missing HttpOnly",
                        summary="A cookie that looks session-related can be accessed by browser-side scripts.",
                        recommendation="Mark session cookies as HttpOnly unless client-side code truly needs access.",
                        evidence={"url": page.url, "cookie_name": cookie.name, "secure": cookie.secure},
                    )
                )

            if cookie.same_site and cookie.same_site.lower() == "none" and not cookie.secure:
                findings.append(
                    _finding(
                        category="samesite_none_without_secure",
                        severity="high",
                        title="Cookie uses SameSite=None without Secure",
                        summary="A cookie marked SameSite=None is not also marked Secure, which weakens cross-site cookie handling.",
                        recommendation="Only use SameSite=None with Secure, or choose a stricter SameSite mode.",
                        evidence={"url": page.url, "cookie_name": cookie.name},
                    )
                )
    return findings


def detect_request_cookies_over_http(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        if not _is_http(page.url):
            continue
        sensitive_cookies = [cookie.name for cookie in page.request_cookies if _looks_sensitive(cookie.name)]
        if not sensitive_cookies:
            continue
        findings.append(
            _finding(
                category="session_cookie_over_http",
                severity="high",
                title="Sensitive cookie sent over HTTP",
                summary="A captured HTTP request includes a cookie that looks session-related.",
                recommendation="Keep session traffic on HTTPS and mark session cookies as Secure.",
                evidence={"url": page.url, "cookie_names": sensitive_cookies},
            )
        )
    return findings


def detect_mixed_content(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        if not _is_https(page.url):
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


def detect_missing_browser_protection_headers(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    for page in pages:
        if not _is_https(page.url) or page.status_code >= 400:
            continue

        if "content-security-policy" not in page.headers:
            findings.append(
                _finding(
                    category="missing_csp",
                    severity="medium",
                    title="HTTPS response missing Content-Security-Policy",
                    summary="A captured HTTPS page does not include a CSP header.",
                    recommendation="Add a focused CSP to reduce the blast radius of injection and mixed-content mistakes.",
                    evidence={"url": page.url},
                )
            )

        referrer_policy = page.headers.get("referrer-policy")
        if not referrer_policy:
            findings.append(
                _finding(
                    category="missing_referrer_policy",
                    severity="low",
                    title="HTTPS response missing Referrer-Policy",
                    summary="A captured HTTPS page does not define how much URL context should be sent as a referrer.",
                    recommendation="Set a Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.",
                    evidence={"url": page.url},
                )
            )
        elif referrer_policy.lower() in {"unsafe-url", "no-referrer-when-downgrade"}:
            findings.append(
                _finding(
                    category="weak_referrer_policy",
                    severity="low",
                    title="Referrer-Policy allows more leakage than needed",
                    summary="The observed Referrer-Policy can leak more browsing context than a stricter setting.",
                    recommendation="Use a stricter Referrer-Policy unless the current behavior is required.",
                    evidence={"url": page.url, "referrer_policy": referrer_policy},
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


def summarize_redirect_downgrades(pages: list[PageRecord]) -> list[dict]:
    paths = []
    by_url = {page.url: page for page in pages}
    for page in pages:
        location = page.headers.get("location")
        if not location or location not in by_url:
            continue
        if _is_https(page.url) and _is_http(location):
            paths.append(
                {
                    "from": page.url,
                    "to": location,
                    "from_host": _host(page.url),
                    "to_host": _host(location),
                    "status_code": page.status_code,
                }
            )
    return paths


def run_detectors(pages: list[PageRecord]) -> list[Finding]:
    findings = []
    findings.extend(detect_downgrade_redirects(pages))
    findings.extend(detect_http_sensitive_submission(pages))
    findings.extend(detect_query_secrets(pages))
    findings.extend(detect_missing_hsts(pages))
    findings.extend(detect_insecure_session_cookies(pages))
    findings.extend(detect_request_cookies_over_http(pages))
    findings.extend(detect_mixed_content(pages))
    findings.extend(detect_missing_browser_protection_headers(pages))
    findings.extend(detect_insecure_cookie_scope(pages))
    return findings
