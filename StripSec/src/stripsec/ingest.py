from __future__ import annotations

import json
from pathlib import Path

from .models import CookieRecord, PageRecord


def _normalize_headers(headers: dict | list | None) -> dict[str, str]:
    if not headers:
        return {}

    if isinstance(headers, list):
        return {
            str(item.get("name", "")).lower(): str(item.get("value", ""))
            for item in headers
            if item.get("name")
        }

    return {str(key).lower(): str(value) for key, value in headers.items()}


def _cookie_from_payload(cookie: dict) -> CookieRecord:
    return CookieRecord(
        name=str(cookie.get("name", "")),
        secure=bool(cookie.get("secure", False)),
        http_only=bool(cookie.get("http_only", cookie.get("httpOnly", False))),
        same_site=cookie.get("same_site") or cookie.get("sameSite"),
        domain=cookie.get("domain"),
        path=cookie.get("path"),
    )


def _cookies_from_payload(cookies: list[dict] | None) -> list[CookieRecord]:
    return [_cookie_from_payload(cookie) for cookie in cookies or [] if cookie.get("name")]


def _load_structured_capture(payload: dict, source_name: str) -> dict:
    pages = []
    for item in payload.get("pages", []):
        pages.append(
            PageRecord(
                url=item["url"],
                status_code=int(item["status_code"]),
                method=str(item.get("method", "GET")).upper(),
                headers=_normalize_headers(item.get("headers")),
                request_headers=_normalize_headers(item.get("request_headers")),
                cookies=_cookies_from_payload(item.get("cookies")),
                request_cookies=_cookies_from_payload(item.get("request_cookies")),
                resources=[str(resource) for resource in item.get("resources", [])],
                form_fields=[str(field).lower() for field in item.get("form_fields", [])],
                post_body=item.get("post_body"),
            )
        )

    return {
        "capture_name": payload.get("capture_name", source_name),
        "format": "stripsec-json",
        "pages": pages,
    }


def _extract_har_form_fields(post_data: dict | None) -> tuple[list[str], str | None]:
    if not post_data:
        return [], None

    fields = [str(param.get("name", "")).lower() for param in post_data.get("params", []) if param.get("name")]
    text = post_data.get("text")
    return fields, text


def _load_har_capture(payload: dict, source_name: str) -> dict:
    entries = payload.get("log", {}).get("entries", [])
    pages: list[PageRecord] = []

    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        form_fields, post_body = _extract_har_form_fields(request.get("postData"))

        pages.append(
            PageRecord(
                url=request["url"],
                status_code=int(response.get("status", 0)),
                method=str(request.get("method", "GET")).upper(),
                headers=_normalize_headers(response.get("headers")),
                request_headers=_normalize_headers(request.get("headers")),
                cookies=_cookies_from_payload(response.get("cookies")),
                request_cookies=_cookies_from_payload(request.get("cookies")),
                resources=[],
                form_fields=form_fields,
                post_body=post_body,
            )
        )

    return {
        "capture_name": payload.get("log", {}).get("comment") or source_name,
        "format": "har",
        "pages": pages,
    }


def load_capture(path: str | Path) -> dict:
    capture_path = Path(path)
    if not capture_path.exists():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    payload = json.loads(capture_path.read_text(encoding="utf-8"))
    if "log" in payload and "entries" in payload["log"]:
        return _load_har_capture(payload, capture_path.stem)
    return _load_structured_capture(payload, capture_path.stem)
