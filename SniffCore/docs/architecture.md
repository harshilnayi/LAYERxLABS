# SniffCore Architecture

## Goal

Turn a Layer 2 capture from a controlled lab into a short list of understandable findings.

## Pipeline

1. Capture intake
   Read `.pcap` or `.pcapng` input from Wireshark or `tshark`.
2. Frame normalization
   Extract timestamps, source and destination MACs, EtherTypes, VLAN tags, ARP fields, DHCP details, and STP metadata.
3. Session summaries
   Build host and protocol summaries such as:
   - unique MAC count
   - per-host frame volume
   - ARP request and reply ratios
   - DHCP offer and ACK behavior
   - BPDU senders
4. Detection layer
   Run detectors for:
   - duplicate IP mapped to multiple MACs
   - one MAC mapped to many IPs in short windows
   - heavy broadcast storms
   - rogue DHCP behavior
   - suspicious STP activity
5. Scoring and evidence
   Attach reasons, counts, and confidence notes to each finding.
6. Reporting
   Export machine-readable and human-readable output.

## Initial Modules

- `ingest.py`
- `models.py`
- `summarize.py`
- `detectors/arp.py`
- `detectors/dhcp.py`
- `detectors/stp.py`
- `reporting.py`
- `cli.py`

## First Deliverable

The first usable version does not need live capture support. File-based ingestion is enough if the reporting is sharp and the detection logic is easy to test.
