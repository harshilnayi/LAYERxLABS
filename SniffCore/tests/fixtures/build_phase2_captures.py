from __future__ import annotations

from pathlib import Path

from scapy.all import ARP, BOOTP, DHCP, Ether, IP, LLC, STP, TCP, UDP, wrpcap


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


def _stp_bpdu(sender_mac: str, root_mac: str, bridge_mac: str):
    return (
        Ether(src=sender_mac, dst="01:80:c2:00:00:00")
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(rootid=4096, rootmac=root_mac, bridgeid=4096, bridgemac=bridge_mac)
    )


def _write_capture(path: Path, frames: list) -> None:
    for index, frame in enumerate(frames):
        frame.time = float(index)
    wrpcap(str(path), frames)


def main() -> None:
    target_dir = Path(__file__).parent
    baseline_path = target_dir / "phase2_baseline_clean.pcap"
    suspect_path = target_dir / "phase2_suspect_lab.pcap"

    client_mac = "02:20:00:00:00:10"
    gateway_mac = "02:20:00:00:00:01"
    dhcp_mac = "02:20:00:00:00:02"
    switch_mac = "02:20:00:00:00:f0"
    rogue_arp_mac = "02:20:00:00:00:99"
    rogue_dhcp_mac = "02:20:00:00:00:77"
    rogue_stp_mac = "02:20:00:00:00:88"

    baseline_frames = [
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=client_mac, psrc="10.10.0.10", pdst="10.10.0.1"),
        Ether(src=gateway_mac, dst=client_mac)
        / ARP(op=2, hwsrc=gateway_mac, psrc="10.10.0.1", hwdst=client_mac, pdst="10.10.0.10"),
        _dhcp_discover(client_mac, xid=1111),
        _dhcp_offer(dhcp_mac, "10.10.0.2", client_mac, "10.10.0.50", xid=1111),
        _stp_bpdu(switch_mac, switch_mac, switch_mac),
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src="10.10.0.10", dst="10.10.0.1")
        / TCP(sport=51515, dport=443, flags="S"),
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src="10.10.0.1", dst="10.10.0.10")
        / TCP(sport=443, dport=51515, flags="SA"),
    ]

    suspect_frames = [
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=client_mac, psrc="10.10.0.10", pdst="10.10.0.1"),
        Ether(src=gateway_mac, dst=client_mac)
        / ARP(op=2, hwsrc=gateway_mac, psrc="10.10.0.1", hwdst=client_mac, pdst="10.10.0.10"),
        Ether(src=rogue_arp_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=rogue_arp_mac, psrc="10.10.0.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.10.0.255"),
        _dhcp_discover(client_mac, xid=2222),
        _dhcp_offer(dhcp_mac, "10.10.0.2", client_mac, "10.10.0.60", xid=2222),
        _dhcp_offer(rogue_dhcp_mac, "10.10.0.254", client_mac, "10.10.0.200", xid=2222),
        _stp_bpdu(switch_mac, switch_mac, switch_mac),
        _stp_bpdu(rogue_stp_mac, rogue_stp_mac, rogue_stp_mac),
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src="10.10.0.10", dst="10.10.0.1")
        / TCP(sport=52525, dport=80, flags="S"),
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src="10.10.0.1", dst="10.10.0.10")
        / TCP(sport=80, dport=52525, flags="SA"),
    ]

    target_dir.mkdir(parents=True, exist_ok=True)
    _write_capture(baseline_path, baseline_frames)
    _write_capture(suspect_path, suspect_frames)
    print(baseline_path)
    print(suspect_path)


if __name__ == "__main__":
    main()
