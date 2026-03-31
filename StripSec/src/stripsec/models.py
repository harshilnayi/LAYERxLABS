from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class CookieRecord:
    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class PageRecord:
    url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[CookieRecord] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["cookies"] = [cookie.to_dict() for cookie in self.cookies]
        return data


@dataclass(slots=True)
class Finding:
    category: str
    severity: str
    score: int
    title: str
    summary: str
    recommendation: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
