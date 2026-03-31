# SniffCore

`SniffCore` is the Layer 2 project in the `LAYERxLABS` series.

The point of this project is not to brag that we opened Wireshark. The point is to take a Layer 2 capture from a lab, break it down, and hand back something another person can understand in a few minutes.

Phase 1 is now working end-to-end.

## What Phase 1 Does

- reads `.pcap` captures from a lab workflow
- extracts source and destination MAC addresses, IP hints, frame sizes, and protocol labels
- summarizes hosts, protocol mix, broadcast traffic, and top talkers
- flags duplicate IP-to-MAC mappings
- flags rapid source-MAC churn inside short windows
- flags captures where broadcast traffic is dominating the frame mix
- writes both JSON and Markdown reports

## Why This Project Is Worth Building

This is the kind of project that sounds better in an interview than "I used Wireshark."

The better story is:

> I built a Layer 2 analysis tool that could take a packet capture from a controlled lab, surface the interesting parts automatically, and generate a report before anyone had to dig through frames by hand.

## Quick Start

Install the package locally:

```powershell
python -m pip install -e .
```

Analyze the sample capture:

```powershell
python -m sniffcore --pcap .\tests\fixtures\sample_phase1_lab.pcap --output-dir .\reports
```

Run the test suite:

```powershell
pytest
```

## Current Output

Each run writes:

- a JSON report for automation or later processing
- a Markdown report for quick review and sharing

## Project Shape

- `src/sniffcore/ingest.py` handles capture loading
- `src/sniffcore/analysis.py` builds host and protocol summaries
- `src/sniffcore/detectors.py` raises the first Layer 2 findings
- `src/sniffcore/reporting.py` writes the report files
- `src/sniffcore/cli.py` runs the project from the command line
- `tests/fixtures/sample_phase1_lab.pcap` is the synthetic lab capture used for validation

## What Comes Next

Phase 2 will push this from useful to sharp:

- stronger ARP spoofing logic
- DHCP anomaly detection
- STP or BPDU-specific checks
- baseline comparison against a known-good capture

## Resume Angle

This project gets strong when we can show numbers:

- captures analyzed
- frames processed
- anomalies raised
- time saved compared with manual packet review

That is the difference between "used Wireshark" and "built a packet-analysis workflow."
