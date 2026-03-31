from __future__ import annotations

from collections import Counter, defaultdict

from .models import FrameRecord, HostSummary


def build_host_summaries(frames: list[FrameRecord]) -> list[HostSummary]:
    summaries: dict[str, HostSummary] = {}

    for frame in frames:
        if frame.src_mac:
            host = summaries.setdefault(frame.src_mac, HostSummary(mac=frame.src_mac))
            host.frames_sent += 1
            host.bytes_sent += frame.length
            if frame.is_broadcast:
                host.broadcast_frames_sent += 1
            if frame.src_ip and frame.src_ip not in host.ips:
                host.ips.append(frame.src_ip)
            if frame.protocol not in host.protocols:
                host.protocols.append(frame.protocol)

        if frame.dst_mac and not frame.is_broadcast:
            host = summaries.setdefault(frame.dst_mac, HostSummary(mac=frame.dst_mac))
            host.frames_received += 1
            host.bytes_received += frame.length
            if frame.dst_ip and frame.dst_ip not in host.ips:
                host.ips.append(frame.dst_ip)
            if frame.protocol not in host.protocols:
                host.protocols.append(frame.protocol)

    return sorted(
        summaries.values(),
        key=lambda item: (item.frames_sent, item.bytes_sent, item.mac),
        reverse=True,
    )


def build_protocol_counts(frames: list[FrameRecord]) -> dict[str, int]:
    counts = Counter(frame.protocol for frame in frames)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def build_top_talkers(hosts: list[HostSummary], limit: int = 5) -> list[dict]:
    top_hosts = sorted(hosts, key=lambda item: (item.frames_sent, item.bytes_sent), reverse=True)[:limit]
    return [
        {
            "mac": host.mac,
            "ips": host.ips,
            "frames_sent": host.frames_sent,
            "bytes_sent": host.bytes_sent,
            "broadcast_frames_sent": host.broadcast_frames_sent,
        }
        for host in top_hosts
    ]


def map_ip_to_macs(frames: list[FrameRecord]) -> dict[str, list[str]]:
    mapping: dict[str, set[str]] = defaultdict(set)
    for frame in frames:
        if frame.src_ip and frame.src_mac:
            mapping[frame.src_ip].add(frame.src_mac)
    return {ip: sorted(macs) for ip, macs in mapping.items() if macs}
