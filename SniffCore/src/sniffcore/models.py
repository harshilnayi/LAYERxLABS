from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class FrameRecord:
    timestamp: float
    length: int
    src_mac: str | None
    dst_mac: str | None
    ether_type: str
    protocol: str
    src_ip: str | None = None
    dst_ip: str | None = None
    is_broadcast: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class HostSummary:
    mac: str
    ips: list[str] = field(default_factory=list)
    frames_sent: int = 0
    frames_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    broadcast_frames_sent: int = 0
    protocols: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    category: str
    severity: str
    title: str
    summary: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
