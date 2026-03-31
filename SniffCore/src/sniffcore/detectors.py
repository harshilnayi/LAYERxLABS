from __future__ import annotations

from collections import Counter

from .analysis import map_ip_to_macs
from .models import Finding, FrameRecord


def detect_duplicate_ip_mappings(frames: list[FrameRecord]) -> list[Finding]:
    findings: list[Finding] = []
    for ip, macs in sorted(map_ip_to_macs(frames).items()):
        if len(macs) < 2:
            continue
        findings.append(
            Finding(
                category="duplicate_ip_mapping",
                severity="high",
                title=f"IP {ip} mapped to multiple MAC addresses",
                summary=(
                    f"The capture shows {ip} being advertised by {len(macs)} different MAC addresses. "
                    "In a lab this usually means spoofing, unstable addressing, or deliberately noisy traffic."
                ),
                evidence={"ip": ip, "mac_addresses": macs, "mac_count": len(macs)},
            )
        )
    return findings


def detect_broadcast_noise(frames: list[FrameRecord]) -> list[Finding]:
    broadcast_frames = [frame for frame in frames if frame.is_broadcast]
    if not frames or len(broadcast_frames) < 5:
        return []

    ratio = len(broadcast_frames) / len(frames)
    if ratio < 0.4:
        return []

    talkers = Counter(frame.src_mac for frame in broadcast_frames if frame.src_mac)
    return [
        Finding(
            category="broadcast_noise",
            severity="medium",
            title="Broadcast traffic dominates the capture",
            summary=(
                f"{len(broadcast_frames)} of {len(frames)} frames are broadcast traffic "
                f"({ratio:.0%} of the capture). That is noisy enough to be worth investigating in a lab review."
            ),
            evidence={
                "broadcast_frames": len(broadcast_frames),
                "total_frames": len(frames),
                "broadcast_ratio": round(ratio, 3),
                "top_broadcast_senders": [
                    {"mac": mac, "frames": count} for mac, count in talkers.most_common(5)
                ],
            },
        )
    ]


def detect_mac_churn(frames: list[FrameRecord], window_seconds: int = 10) -> list[Finding]:
    if len(frames) < 6:
        return []

    ordered = sorted(frames, key=lambda frame: frame.timestamp)
    findings: list[Finding] = []

    for index, frame in enumerate(ordered):
        window_end = frame.timestamp + window_seconds
        window = [item for item in ordered[index:] if item.timestamp <= window_end]
        unique_macs = sorted({item.src_mac for item in window if item.src_mac})
        if len(window) >= 6 and len(unique_macs) >= 5:
            findings.append(
                Finding(
                    category="mac_churn",
                    severity="medium",
                    title="Rapid source-MAC churn detected",
                    summary=(
                        f"Within {window_seconds} seconds the capture shows {len(unique_macs)} unique source MAC addresses "
                        f"across {len(window)} frames. That pattern is worth checking for MAC flooding or staged lab traffic."
                    ),
                    evidence={
                        "window_seconds": window_seconds,
                        "frame_count": len(window),
                        "unique_source_macs": unique_macs,
                    },
                )
            )
            break

    return findings


def run_phase1_detectors(frames: list[FrameRecord]) -> list[Finding]:
    findings = []
    findings.extend(detect_duplicate_ip_mappings(frames))
    findings.extend(detect_mac_churn(frames))
    findings.extend(detect_broadcast_noise(frames))
    return findings
