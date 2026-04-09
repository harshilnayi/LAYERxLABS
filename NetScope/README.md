# NetScope

`NetScope` is the Layer 1 project in the `LAYERxLABS` series.

It focuses on rogue-device investigation and local-network visibility. The goal is simple: scan a target segment, compare what shows up against a known baseline, and turn the results into something easier to review than raw Nmap output.

## What It Does

- runs Nmap-based investigation scans against a target range
- parses Nmap XML directly
- tracks approved devices in a JSON baseline
- flags hosts as `known`, `unknown`, or `suspicious`
- writes JSON, CSV, Markdown, and HTML reports

## Project Shape

- `netscope/cli.py` runs the command-line workflow
- `netscope/nmap_runner.py` builds and runs Nmap commands, then parses XML output
- `netscope/analyzer.py` scores and classifies observed hosts
- `netscope/baseline.py` stores and loads approved devices
- `netscope/reporter.py` writes the final reports
- `tests/` covers parsing, analysis, reporting, and Nmap command construction

## Install

```powershell
python -m pip install -e .
```

Nmap must also be installed and available on `PATH` for live scans.

## Quick Start

Create a baseline file:

```powershell
python -m netscope.cli init-baseline
```

Add approved devices:

```powershell
python -m netscope.cli add-device --name "Office Laptop" --mac "AA:BB:CC:DD:EE:FF" --owner "Security Team"
python -m netscope.cli add-device --name "Printer" --ip "192.168.1.50"
```

Run an investigation scan:

```powershell
python -m netscope.cli investigate --targets "192.168.1.0/24"
```

If you want OS detection as part of a deeper scan, add it explicitly:

```powershell
python -m netscope.cli investigate --targets "192.168.1.0/24" --extra-arg=-O
```

Analyze an existing XML file:

```powershell
python -m netscope.cli investigate --xml-input ".\tests\fixtures\sample_nmap.xml"
```

Run the tests:

```powershell
python -m unittest discover -s tests -v
```

## Current Notes

This project is built as a practical investigation aid for a controlled lab. It is meant to help review what appeared on a network segment, compare it with expected devices, and keep the findings in a format that is easy to revisit.
