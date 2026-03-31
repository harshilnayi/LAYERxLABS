from __future__ import annotations

from .analysis import build_protocol_counts, map_ip_to_macs
from .models import FrameRecord


def build_baseline_profile(frames: list[FrameRecord]) -> dict:
    return {
        "source_macs": sorted({frame.src_mac for frame in frames if frame.src_mac}),
        "protocols": build_protocol_counts(frames),
        "ip_to_macs": map_ip_to_macs(frames),
        "dhcp_servers": sorted(
            {
                frame.src_mac
                for frame in frames
                if frame.protocol == "DHCP"
                and frame.src_mac
                and frame.metadata.get("dhcp_message_type") in {"offer", "ack", "nak"}
            }
        ),
        "stp_senders": sorted({frame.src_mac for frame in frames if frame.protocol == "STP" and frame.src_mac}),
        "stp_root_macs": sorted(
            {
                frame.metadata["stp_root_mac"]
                for frame in frames
                if frame.protocol == "STP" and frame.metadata.get("stp_root_mac")
            }
        ),
    }


def compare_against_baseline(frames: list[FrameRecord], baseline_profile: dict) -> dict:
    current_source_macs = sorted({frame.src_mac for frame in frames if frame.src_mac})
    current_protocols = set(build_protocol_counts(frames))
    current_dhcp_servers = sorted(
        {
            frame.src_mac
            for frame in frames
            if frame.protocol == "DHCP"
            and frame.src_mac
            and frame.metadata.get("dhcp_message_type") in {"offer", "ack", "nak"}
        }
    )
    current_stp_senders = sorted({frame.src_mac for frame in frames if frame.protocol == "STP" and frame.src_mac})

    return {
        "new_source_macs": sorted(set(current_source_macs) - set(baseline_profile["source_macs"])),
        "new_protocols": sorted(current_protocols - set(baseline_profile["protocols"])),
        "new_dhcp_servers": sorted(set(current_dhcp_servers) - set(baseline_profile["dhcp_servers"])),
        "new_stp_senders": sorted(set(current_stp_senders) - set(baseline_profile["stp_senders"])),
        "baseline_dhcp_servers": baseline_profile["dhcp_servers"],
        "baseline_stp_senders": baseline_profile["stp_senders"],
    }
