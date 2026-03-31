# SniffCore Roadmap

## Milestone 1: Skeleton

- set up package structure
- define core data models
- choose capture-ingestion path
- add first fixture captures

## Milestone 2: Baseline Reporting

- parse a capture into normalized records
- count hosts, MACs, ARP frames, DHCP frames, and STP frames
- generate a Markdown summary that reads cleanly
- add tests for parsing edge cases

## Milestone 3: Detection

- ARP spoofing detector
- DHCP anomaly detector
- STP/BPDU anomaly detector
- noisy broadcast detector

## Milestone 4: Evidence

- JSON export for automation
- HTML report for presentation
- severity scoring with reason strings
- before/after comparison against a known-good capture

## Milestone 5: Portfolio Finish

- final screenshots
- write-up with setup, findings, and lessons learned
- metrics table for resume bullets
- clean sample data and repeatable demo steps

## Definition of Done

We are done when someone can clone the repo, run the analysis against a sample capture, and understand the main Layer 2 issues without opening Wireshark.
