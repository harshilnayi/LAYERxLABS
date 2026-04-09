from __future__ import annotations

from pathlib import Path

from scapy.all import ARP, BOOTP, DHCP, Ether, IP, LLC, STP, TCP, UDP, wrpcap


def _write_capture(path: Path, frames: list) -> None:
    for index, frame in enumerate(frames):
        frame.time = float(index)
    wrpcap(str(path), frames)


def _dhcp_discover(client_mac: str, xid: int):
    return (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=xid)
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def _dhcp_offer(server_mac: str, server_ip: str, client_mac: str, yiaddr: str, xid: int):
    return (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")), yiaddr=yiaddr, siaddr=server_ip, xid=xid)
        / DHCP(options=[("message-type", "offer"), ("server_id", server_ip), "end"])
    )


def _stp_bpdu(sender_mac: str):
    return (
        Ether(src=sender_mac, dst="01:80:c2:00:00:00")
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(rootid=4096, rootmac=sender_mac, bridgeid=4096, bridgemac=sender_mac)
    )


def main() -> None:
    target_dir = Path(__file__).parent

    quiet_path = target_dir / "phase1_quiet_lab.pcap"
    chatty_path = target_dir / "phase1_chatty_but_ok.pcap"
    growth_baseline_path = target_dir / "phase2_growth_baseline.pcap"
    growth_capture_path = target_dir / "phase2_growth_capture.pcap"

    gateway = "02:30:00:00:00:01"
    workstation = "02:30:00:00:00:10"
    printer = "02:30:00:00:00:20"
    scanner = "02:30:00:00:00:30"
    dhcp_server = "02:30:00:00:00:02"
    switch = "02:30:00:00:00:f0"
    laptop = "02:30:00:00:00:40"
    phone = "02:30:00:00:00:41"

    quiet_frames = [
        Ether(src=workstation, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=workstation, psrc="10.20.0.10", pdst="10.20.0.1"),
        Ether(src=gateway, dst=workstation)
        / ARP(op=2, hwsrc=gateway, psrc="10.20.0.1", hwdst=workstation, pdst="10.20.0.10"),
        Ether(src=workstation, dst=gateway)
        / IP(src="10.20.0.10", dst="10.20.0.1")
        / TCP(sport=50100, dport=443, flags="S"),
        Ether(src=gateway, dst=workstation)
        / IP(src="10.20.0.1", dst="10.20.0.10")
        / TCP(sport=443, dport=50100, flags="SA"),
        Ether(src=workstation, dst=gateway)
        / IP(src="10.20.0.10", dst="10.20.0.1")
        / TCP(sport=50100, dport=443, flags="A"),
    ]

    chatty_frames = [
        Ether(src=workstation, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=workstation, psrc="10.21.0.10", pdst="10.21.0.1"),
        Ether(src=printer, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=printer, psrc="10.21.0.20", pdst="10.21.0.1"),
        Ether(src=scanner, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=scanner, psrc="10.21.0.30", pdst="10.21.0.1"),
        Ether(src=gateway, dst=workstation)
        / ARP(op=2, hwsrc=gateway, psrc="10.21.0.1", hwdst=workstation, pdst="10.21.0.10"),
        Ether(src=gateway, dst=printer)
        / ARP(op=2, hwsrc=gateway, psrc="10.21.0.1", hwdst=printer, pdst="10.21.0.20"),
        Ether(src=gateway, dst=scanner)
        / ARP(op=2, hwsrc=gateway, psrc="10.21.0.1", hwdst=scanner, pdst="10.21.0.30"),
        Ether(src=workstation, dst=gateway)
        / IP(src="10.21.0.10", dst="10.21.0.1")
        / TCP(sport=51000, dport=443, flags="S"),
        Ether(src=gateway, dst=workstation)
        / IP(src="10.21.0.1", dst="10.21.0.10")
        / TCP(sport=443, dport=51000, flags="SA"),
        Ether(src=printer, dst=gateway)
        / IP(src="10.21.0.20", dst="10.21.0.1")
        / TCP(sport=9100, dport=443, flags="S"),
        Ether(src=scanner, dst=gateway)
        / IP(src="10.21.0.30", dst="10.21.0.1")
        / TCP(sport=52000, dport=443, flags="S"),
    ]

    growth_baseline_frames = [
        Ether(src=workstation, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=workstation, psrc="10.22.0.10", pdst="10.22.0.1"),
        Ether(src=gateway, dst=workstation)
        / ARP(op=2, hwsrc=gateway, psrc="10.22.0.1", hwdst=workstation, pdst="10.22.0.10"),
        _dhcp_discover(workstation, xid=3001),
        _dhcp_offer(dhcp_server, "10.22.0.2", workstation, "10.22.0.10", xid=3001),
        _stp_bpdu(switch),
        Ether(src=workstation, dst=gateway)
        / IP(src="10.22.0.10", dst="10.22.0.1")
        / TCP(sport=53000, dport=443, flags="S"),
        Ether(src=gateway, dst=workstation)
        / IP(src="10.22.0.1", dst="10.22.0.10")
        / TCP(sport=443, dport=53000, flags="SA"),
    ]

    growth_frames = [
        Ether(src=workstation, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=workstation, psrc="10.22.0.10", pdst="10.22.0.1"),
        Ether(src=gateway, dst=workstation)
        / ARP(op=2, hwsrc=gateway, psrc="10.22.0.1", hwdst=workstation, pdst="10.22.0.10"),
        _dhcp_discover(workstation, xid=3002),
        _dhcp_offer(dhcp_server, "10.22.0.2", workstation, "10.22.0.10", xid=3002),
        _stp_bpdu(switch),
        Ether(src=laptop, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=laptop, psrc="10.22.0.40", pdst="10.22.0.1"),
        Ether(src=phone, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=phone, psrc="10.22.0.41", pdst="10.22.0.1"),
        Ether(src=gateway, dst=laptop)
        / ARP(op=2, hwsrc=gateway, psrc="10.22.0.1", hwdst=laptop, pdst="10.22.0.40"),
        Ether(src=workstation, dst=gateway)
        / IP(src="10.22.0.10", dst="10.22.0.1")
        / TCP(sport=53000, dport=443, flags="S"),
        Ether(src=laptop, dst=gateway)
        / IP(src="10.22.0.40", dst="10.22.0.1")
        / TCP(sport=53010, dport=443, flags="S"),
    ]

    target_dir.mkdir(parents=True, exist_ok=True)
    _write_capture(quiet_path, quiet_frames)
    _write_capture(chatty_path, chatty_frames)
    _write_capture(growth_baseline_path, growth_baseline_frames)
    _write_capture(growth_capture_path, growth_frames)

    print(quiet_path)
    print(chatty_path)
    print(growth_baseline_path)
    print(growth_capture_path)


if __name__ == "__main__":
    main()
