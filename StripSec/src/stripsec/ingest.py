from __future__ import annotations

import json
from pathlib import Path

from .models import CookieRecord, PageRecord


def load_capture(path: str | Path) -> dict:
    capture_path = Path(path)
    if not capture_path.exists():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    payload = json.loads(capture_path.read_text(encoding="utf-8"))
    pages = []
    for item in payload.get("pages", []):
        pages.append(
            PageRecord(
                url=item["url"],
                status_code=item["status_code"],
                headers={str(key).lower(): str(value) for key, value in item.get("headers", {}).items()},
                cookies=[
                    CookieRecord(
                        name=cookie["name"],
                        secure=bool(cookie.get("secure", False)),
                        http_only=bool(cookie.get("http_only", False)),
                        same_site=cookie.get("same_site"),
                    )
                    for cookie in item.get("cookies", [])
                ],
                resources=[str(resource) for resource in item.get("resources", [])],
            )
        )

    return {
        "capture_name": payload.get("capture_name", capture_path.stem),
        "pages": pages,
    }
