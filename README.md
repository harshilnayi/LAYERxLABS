# LAYERxLABS

`LAYERxLABS` is the home base for a three-project security lab series built around real networking layers and hands-on learning.

The goal is simple: ship projects that look like they came from people who actually used the tools, wrote down what mattered, and understood the tradeoffs.

## Projects

### NetScope

Layer 1 rogue-device investigation and network visibility work.

Current status: built, cleaned up, and tested inside the monorepo.

### SniffCore

Layer 2 packet-capture analysis project focused on turning raw traffic into findings that are easy to review and understand.

Current status: complete with baseline-aware checks, scored findings, and HTML reporting.

### StripSec

Layer 5 transport and session-review project for captured web traffic.

Current status: complete with JSON and HAR ingestion, downgrade-path analysis, session-cookie review, browser-policy checks, and HTML reporting.

## Repo Layout

```text
LAYERxLABS/
|-- NetScope/
|-- SniffCore/
|   |-- docs/
|   |-- src/sniffcore/
|   `-- tests/
|-- StripSec/
|   |-- docs/
|   |-- src/stripsec/
|   `-- tests/
`-- reports/
```

## What We Care About

- Clear project scope instead of tool dumping
- Reproducible lab work
- Evidence that can be shared cleanly and revisited later
- Writeups that sound like engineers, not brochure copy

## Ground Rules

Everything in this repo is meant for isolated, permitted lab work. The value here is in analysis, reporting, and understanding what the traffic means, not in trying to turn the repo into an attack launcher.

## Current Focus

All three project folders are now active. Each one is meant to stand on its own, but the repo works best as a set:

- `NetScope` for Layer 1 visibility and rogue-device investigation
- `SniffCore` for Layer 2 capture analysis and anomaly reporting
- `StripSec` for Layer 5 transport and session review
