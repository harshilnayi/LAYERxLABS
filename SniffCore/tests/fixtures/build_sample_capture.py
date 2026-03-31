from __future__ import annotations

from pathlib import Path

from scapy.all import ARP, Ether, IP, TCP, wrpcap


def main() -> None:
    target = Path(__file__).with_name("sample_phase1_lab.pcap")

    frames = []

    host_a = "02:10:00:00:00:0a"
    gateway = "02:10:00:00:00:01"
    rogue_a = "02:10:00:00:00:50"
    rogue_b = "02:10:00:00:00:51"
    flooders = [
        "02:10:00:00:00:60",
        "02:10:00:00:00:61",
        "02:10:00:00:00:62",
        "02:10:00:00:00:63",
        "02:10:00:00:00:64",
    ]

    frames.append(
        Ether(src=host_a, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=host_a, psrc="10.0.0.10", pdst="10.0.0.1")
    )
    frames.append(
        Ether(src=gateway, dst=host_a)
        / ARP(op=2, hwsrc=gateway, psrc="10.0.0.1", hwdst=host_a, pdst="10.0.0.10")
    )
    frames.append(
        Ether(src=host_a, dst=gateway)
        / IP(src="10.0.0.10", dst="10.0.0.1")
        / TCP(sport=51515, dport=443, flags="S")
    )
    frames.append(
        Ether(src=gateway, dst=host_a)
        / IP(src="10.0.0.1", dst="10.0.0.10")
        / TCP(sport=443, dport=51515, flags="SA")
    )
    frames.append(
        Ether(src=rogue_a, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=rogue_a, psrc="10.0.0.50", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.255")
    )
    frames.append(
        Ether(src=rogue_b, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=rogue_b, psrc="10.0.0.50", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.255")
    )

    for index, mac in enumerate(flooders, start=1):
        frame = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, hwsrc=mac, psrc=f"10.0.0.{90 + index}", pdst="10.0.0.254")
        )
        frame.time = 6 + index
        frames.append(frame)

    for packet_index, frame in enumerate(frames):
        frame.time = float(packet_index)

    target.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(target), frames)
    print(target)


if __name__ == "__main__":
    main()
