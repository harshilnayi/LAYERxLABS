# SniffCore

`SniffCore` is the Layer 2 project in the `LAYERxLABS` series.

The point of this project is not to brag that we opened Wireshark. The point is to take a Layer 2 capture from a lab, break it down, and hand back something another person can understand in a few minutes.

Phase 3 is now working end-to-end.

## What It Does Right Now

- reads `.pcap` captures from a lab workflow
- extracts source and destination MAC addresses, IP hints, frame sizes, protocol labels, and protocol-specific metadata
- summarizes hosts, protocol mix, broadcast traffic, and top talkers
- flags duplicate IP-to-MAC mappings
- flags rapid source-MAC churn inside short windows
- flags captures where broadcast traffic is dominating the frame mix
- raises ARP spoofing findings when ARP replies drift away from expected mappings
- flags DHCP server anomalies, including offers from servers outside a known-good baseline
- flags STP sender drift and unexpected BPDU sources
- compares a suspicious capture against a known-good baseline capture
- assigns severity scores and recommended next actions for each finding
- writes JSON, Markdown, and HTML reports

## Why This Project Is Worth Building

This project is useful because it turns a pile of Layer 2 traffic into something easier to reason about.

The core idea is:

> I built a Layer 2 analysis tool that could take a packet capture from a controlled lab, surface the interesting parts automatically, and generate a report before anyone had to dig through frames by hand.

## Quick Start

Install the package locally:

```powershell
python -m pip install -e .
```

Analyze the sample Phase 1 capture:

```powershell
python -m sniffcore --pcap .\tests\fixtures\sample_phase1_lab.pcap --output-dir .\reports
```

Run a baseline-aware Phase 2 comparison:

```powershell
python -m sniffcore --pcap .\tests\fixtures\phase2_suspect_lab.pcap --baseline-pcap .\tests\fixtures\phase2_baseline_clean.pcap --output-dir .\reports
```

Run the test suite:

```powershell
pytest
```

## Current Output

Each run writes:

- a JSON report for automation or later processing
- a Markdown report for quick review and sharing
- an HTML dashboard that is easier to review and share

## Project Shape

- `src/sniffcore/ingest.py` handles capture loading
- `src/sniffcore/analysis.py` builds host and protocol summaries
- `src/sniffcore/baseline.py` builds and compares known-good capture profiles
- `src/sniffcore/detectors.py` raises the first Layer 2 findings
- `src/sniffcore/reporting.py` writes the report files
- `src/sniffcore/cli.py` runs the project from the command line
- `tests/fixtures/sample_phase1_lab.pcap` is the synthetic lab capture used for validation
- `tests/fixtures/phase2_baseline_clean.pcap` and `tests/fixtures/phase2_suspect_lab.pcap` drive the baseline-aware checks
- `docs/demo-walkthrough.md` is the short case-study path for showing the project to someone else

## What Comes Next

The next round is polish work:

- one polished end-to-end writeup with screenshots
- a cleaner metrics summary across more fixtures
- fixture expansion beyond the two current scenarios
- final prep for the Layer 5 follow-up project

## Learning Value

This project gets strong when we can show numbers:

- captures analyzed
- frames processed
- anomalies raised
- time saved compared with manual packet review

That is the difference between "used Wireshark" and "built a packet-analysis workflow."
