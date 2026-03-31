# SniffCore

`SniffCore` is the Layer 2 project in the `LAYERxLABS` series.

The point of this project is not to brag that we opened Wireshark. The point is to show that we can take Layer 2 traffic from a controlled lab, break it down, and turn it into findings that make sense to someone else.

## Project Direction

`SniffCore` will focus on packet capture, analysis, and reporting inside a legal lab environment.

If Yersinia is used at all, it will only be used to generate test traffic inside an isolated lab. `SniffCore` itself should stay on the analysis side:

- ingest `.pcap` or `.pcapng` files
- extract Layer 2 and adjacent metadata
- detect suspicious switching and local-network patterns
- score findings
- export evidence in clean formats

That makes the project stronger, safer, and much easier to defend in an interview.

## Core Outcome

By the time this project is done, we should be able to say:

> We built a Layer 2 traffic analysis workflow that can take a lab capture, highlight ARP, DHCP, STP, and MAC-table abuse indicators, and produce a report that an analyst can read without opening Wireshark first.

## Planned Feature Set

### Phase 1

- import packet captures
- summarize hosts, MAC addresses, protocols, and top talkers
- flag duplicate IP-to-MAC mappings
- flag sudden MAC churn and noisy broadcast behavior
- export JSON and Markdown reports

### Phase 2

- detect ARP spoofing indicators
- detect DHCP starvation or rogue DHCP patterns
- detect suspicious BPDU or STP activity from non-infrastructure hosts
- compare one capture against a known-good baseline

### Phase 3

- add a cleaner HTML report
- add sample lab datasets
- add simple charts for protocol distribution and anomaly counts
- write a polished case-study report for the final portfolio

## Suggested Tech Stack

- Wireshark or `tshark` for capture and packet export
- Python for parsing, scoring, and report generation
- `scapy` where custom packet inspection helps
- `pytest` for parser and detector tests

## Folder Guide

- `docs/architecture.md` explains how the pipeline should fit together
- `docs/roadmap.md` breaks the work into milestones
- `src/sniffcore/` will hold the package code
- `tests/` will hold fixtures and detector coverage

## Resume Value

This project becomes strong resume material if we can show:

- how many captures were analyzed
- how many devices and frames were processed
- what kinds of anomalies were detected
- how much review time the generated report saved compared to raw packet inspection

That is the difference between “used Wireshark” and “built a packet-analysis workflow.”
