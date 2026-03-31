from __future__ import annotations

from pathlib import Path

from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapReader

from .models import FrameRecord


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    return value.replace("-", ":").lower()


def _detect_protocol(packet) -> tuple[str, str, str | None, str | None]:
    if packet.haslayer(ARP):
        arp = packet[ARP]
        return "arp", "ARP", arp.psrc or None, arp.pdst or None

    if packet.haslayer(IP):
        ip = packet[IP]
        if packet.haslayer(DHCP):
            return "ipv4", "DHCP", ip.src or None, ip.dst or None
        if packet.haslayer(TCP):
            return "ipv4", "TCP", ip.src or None, ip.dst or None
        if packet.haslayer(UDP):
            return "ipv4", "UDP", ip.src or None, ip.dst or None
        return "ipv4", "IPv4", ip.src or None, ip.dst or None

    return "unknown", "Ethernet", None, None


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
            ether_type, protocol, src_ip, dst_ip = _detect_protocol(packet)
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
                )
            )

    return frames
