from __future__ import annotations

from pathlib import Path

from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether, STP
from scapy.utils import PcapReader

from .models import FrameRecord


DHCP_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    return value.replace("-", ":").lower()


def _decode_dhcp_message_type(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, bytes):
        if len(value) == 1:
            return DHCP_MESSAGE_TYPES.get(value[0], str(value[0]))
        return value.decode("utf-8", errors="ignore").lower()
    if isinstance(value, int):
        return DHCP_MESSAGE_TYPES.get(value, str(value))
    return str(value).lower()


def _stringify(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _extract_dhcp_options(packet) -> dict[str, str | bytes | int]:
    options: dict[str, str | bytes | int] = {}
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) >= 2:
            key, value = option[0], option[1]
            options[str(key)] = value
    return options


def _detect_protocol(packet) -> tuple[str, str, str | None, str | None, dict]:
    if packet.haslayer(STP):
        stp = packet[STP]
        return (
            "stp",
            "STP",
            None,
            None,
            {
                "stp_root_mac": normalize_mac(getattr(stp, "rootmac", None)),
                "stp_bridge_mac": normalize_mac(getattr(stp, "bridgemac", None)),
                "stp_root_id": int(getattr(stp, "rootid", 0)),
                "stp_bridge_id": int(getattr(stp, "bridgeid", 0)),
                "stp_bpdu_type": int(getattr(stp, "bpdutype", 0)),
            },
        )

    if packet.haslayer(ARP):
        arp = packet[ARP]
        return (
            "arp",
            "ARP",
            arp.psrc or None,
            arp.pdst or None,
            {
                "arp_op": int(arp.op),
                "arp_hwsrc": normalize_mac(getattr(arp, "hwsrc", None)),
                "arp_hwdst": normalize_mac(getattr(arp, "hwdst", None)),
            },
        )

    if packet.haslayer(IP):
        ip = packet[IP]
        if packet.haslayer(DHCP):
            options = _extract_dhcp_options(packet)
            return (
                "ipv4",
                "DHCP",
                ip.src or None,
                ip.dst or None,
                {
                    "dhcp_message_type": _decode_dhcp_message_type(options.get("message-type")),
                    "dhcp_server_id": _stringify(options.get("server_id")),
                },
            )
        if packet.haslayer(TCP):
            return "ipv4", "TCP", ip.src or None, ip.dst or None, {}
        if packet.haslayer(UDP):
            return "ipv4", "UDP", ip.src or None, ip.dst or None, {}
        return "ipv4", "IPv4", ip.src or None, ip.dst or None, {}

    return "unknown", "Ethernet", None, None, {}


def load_capture(path: str | Path) -> list[FrameRecord]:
    capture_path = Path(path)
    if not capture_path.exists():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    frames: list[FrameRecord] = []
    with PcapReader(str(capture_path)) as reader:
        for packet in reader:
            if not packet.haslayer(Ether):
                continue

            ether = packet[Ether]
            ether_type, protocol, src_ip, dst_ip, metadata = _detect_protocol(packet)
            src_mac = normalize_mac(getattr(ether, "src", None))
            dst_mac = normalize_mac(getattr(ether, "dst", None))

            frames.append(
                FrameRecord(
                    timestamp=float(packet.time),
                    length=len(packet),
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    ether_type=ether_type,
                    protocol=protocol,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    is_broadcast=dst_mac == "ff:ff:ff:ff:ff:ff",
                    metadata=metadata,
                )
            )

    return frames
