from __future__ import annotations

from collections import Counter, defaultdict

from .analysis import map_ip_to_macs
from .models import Finding, FrameRecord


SEVERITY_SCORES = {
    "low": 30,
    "medium": 60,
    "high": 90,
}


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


def detect_duplicate_ip_mappings(frames: list[FrameRecord]) -> list[Finding]:
    findings: list[Finding] = []
    for ip, macs in sorted(map_ip_to_macs(frames).items()):
        if len(macs) < 2:
            continue
        findings.append(
            _finding(
                category="duplicate_ip_mapping",
                severity="high",
                title=f"IP {ip} mapped to multiple MAC addresses",
                summary=(
                    f"The capture shows {ip} being advertised by {len(macs)} different MAC addresses. "
                    "In a lab this usually means spoofing, unstable addressing, or deliberately noisy traffic."
                ),
                recommendation="Validate the expected owner of this IP and check which MAC should be authoritative.",
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
        _finding(
            category="broadcast_noise",
            severity="medium",
            title="Broadcast traffic dominates the capture",
            summary=(
                f"{len(broadcast_frames)} of {len(frames)} frames are broadcast traffic "
                f"({ratio:.0%} of the capture). That is noisy enough to be worth investigating in a lab review."
            ),
            recommendation="Check whether the broadcast spike is expected test traffic or a sign of unstable local-network behavior.",
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
                _finding(
                    category="mac_churn",
                    severity="medium",
                    title="Rapid source-MAC churn detected",
                    summary=(
                        f"Within {window_seconds} seconds the capture shows {len(unique_macs)} unique source MAC addresses "
                        f"across {len(window)} frames. That pattern is worth checking for MAC flooding or staged lab traffic."
                    ),
                    recommendation="Review whether the churn came from deliberate fixture traffic or from a switch-flood style event in the lab.",
                    evidence={
                        "window_seconds": window_seconds,
                        "frame_count": len(window),
                        "unique_source_macs": unique_macs,
                    },
                )
            )
            break

    return findings


def detect_arp_spoofing(frames: list[FrameRecord], baseline_profile: dict | None = None) -> list[Finding]:
    arp_replies = [
        frame
        for frame in frames
        if frame.protocol == "ARP"
        and frame.metadata.get("arp_op") == 2
        and frame.src_ip
        and frame.src_mac
    ]

    claims: dict[str, set[str]] = defaultdict(set)
    for frame in arp_replies:
        claims[frame.src_ip].add(frame.src_mac)

    findings: list[Finding] = []
    for ip, macs in sorted(claims.items()):
        baseline_macs = set((baseline_profile or {}).get("ip_to_macs", {}).get(ip, []))
        unexpected_macs = sorted(set(macs) - baseline_macs) if baseline_macs else []

        if len(macs) < 2 and not unexpected_macs:
            continue

        findings.append(
            _finding(
                category="arp_spoofing",
                severity="high",
                title=f"ARP reply drift detected for {ip}",
                summary=(
                    f"ARP replies in the capture associate {ip} with {len(macs)} source MAC addresses. "
                    "That is a strong hint of spoofing, cache poisoning, or deliberate lab interference."
                ),
                recommendation="Compare the observed ARP replies with the expected gateway or host mapping before trusting the segment.",
                evidence={
                    "ip": ip,
                    "observed_reply_macs": sorted(macs),
                    "baseline_reply_macs": sorted(baseline_macs),
                    "unexpected_macs": unexpected_macs,
                },
            )
        )

    return findings


def detect_dhcp_anomalies(frames: list[FrameRecord], baseline_profile: dict | None = None) -> list[Finding]:
    server_frames = [
        frame
        for frame in frames
        if frame.protocol == "DHCP"
        and frame.src_mac
        and frame.metadata.get("dhcp_message_type") in {"offer", "ack", "nak"}
    ]
    if not server_frames:
        return []

    server_macs = sorted({frame.src_mac for frame in server_frames if frame.src_mac})
    findings: list[Finding] = []

    if len(server_macs) > 1:
        findings.append(
            _finding(
                category="dhcp_anomaly",
                severity="high",
                title="Multiple DHCP servers answered in the same capture",
                summary=(
                    f"The capture contains DHCP server responses from {len(server_macs)} different MAC addresses. "
                    "In a controlled lab that is usually enough to justify a closer look for rogue DHCP behavior."
                ),
                recommendation="Verify which DHCP server should be active and isolate any extra responder before trusting new leases.",
                evidence={"server_macs": server_macs},
            )
        )

    baseline_servers = sorted((baseline_profile or {}).get("dhcp_servers", []))
    unexpected_servers = sorted(set(server_macs) - set(baseline_servers)) if baseline_servers else []
    if unexpected_servers:
        findings.append(
            _finding(
                category="rogue_dhcp_server",
                severity="high",
                title="DHCP responses came from a server outside the baseline",
                summary=(
                    "A DHCP server responded from a MAC address that does not appear in the known-good baseline capture."
                ),
                recommendation="Treat leases from the unexpected server as untrusted until the server identity is confirmed.",
                evidence={
                    "baseline_servers": baseline_servers,
                    "unexpected_servers": unexpected_servers,
                },
            )
        )

    return findings


def detect_stp_anomalies(frames: list[FrameRecord], baseline_profile: dict | None = None) -> list[Finding]:
    stp_frames = [frame for frame in frames if frame.protocol == "STP" and frame.src_mac]
    if not stp_frames:
        return []

    senders = sorted({frame.src_mac for frame in stp_frames if frame.src_mac})
    root_macs = sorted(
        {frame.metadata.get("stp_root_mac") for frame in stp_frames if frame.metadata.get("stp_root_mac")}
    )
    findings: list[Finding] = []

    if len(senders) > 1:
        findings.append(
            _finding(
                category="stp_topology_change",
                severity="medium",
                title="More than one STP sender appeared in the capture",
                summary=(
                    f"STP frames were sourced by {len(senders)} different MAC addresses. "
                    "That can indicate topology drift, rogue switching behavior, or staged lab traffic."
                ),
                recommendation="Check whether the extra BPDU sender is a trusted switch before allowing it to influence topology decisions.",
                evidence={"stp_senders": senders, "root_macs": root_macs},
            )
        )

    baseline_senders = sorted((baseline_profile or {}).get("stp_senders", []))
    unexpected_senders = sorted(set(senders) - set(baseline_senders)) if baseline_senders else []
    if unexpected_senders:
        findings.append(
            _finding(
                category="stp_sender_drift",
                severity="high",
                title="A new STP sender appeared outside the baseline",
                summary=(
                    "The capture includes BPDU traffic from a MAC address that was not present in the baseline capture."
                ),
                recommendation="Validate the role of the new STP sender and make sure it is not an unauthorized bridge.",
                evidence={
                    "baseline_stp_senders": baseline_senders,
                    "unexpected_stp_senders": unexpected_senders,
                    "observed_root_macs": root_macs,
                },
            )
        )

    return findings


def detect_baseline_drift(frames: list[FrameRecord], baseline_profile: dict | None = None) -> list[Finding]:
    if not baseline_profile:
        return []

    current_source_macs = sorted({frame.src_mac for frame in frames if frame.src_mac})
    new_source_macs = sorted(set(current_source_macs) - set(baseline_profile["source_macs"]))
    if len(new_source_macs) < 2:
        return []

    return [
        _finding(
            category="baseline_drift",
            severity="medium",
            title="The capture contains new source MAC addresses compared with the baseline",
            summary=(
                f"{len(new_source_macs)} source MAC addresses in the capture were not present in the known-good baseline."
            ),
            recommendation="Use the baseline drift list to separate expected lab additions from genuinely suspicious senders.",
            evidence={
                "new_source_macs": new_source_macs,
                "baseline_source_macs": baseline_profile["source_macs"],
            },
        )
    ]


def run_detectors(frames: list[FrameRecord], baseline_profile: dict | None = None) -> list[Finding]:
    findings = []
    findings.extend(detect_duplicate_ip_mappings(frames))
    findings.extend(detect_mac_churn(frames))
    findings.extend(detect_broadcast_noise(frames))
    findings.extend(detect_arp_spoofing(frames, baseline_profile=baseline_profile))
    findings.extend(detect_dhcp_anomalies(frames, baseline_profile=baseline_profile))
    findings.extend(detect_stp_anomalies(frames, baseline_profile=baseline_profile))
    findings.extend(detect_baseline_drift(frames, baseline_profile=baseline_profile))
    return findings
