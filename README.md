# LAYERxLABS

`LAYERxLABS` is the home base for a three-project security lab series built around real networking layers and real interview stories.

The goal is simple: ship projects that look like they came from people who actually used the tools, wrote down what mattered, and understood the tradeoffs.

## Projects

### NetScope

Layer 1 rogue-device investigation and network visibility work.

Current status: review and hardening stage.

### SniffCore

Layer 2 packet-capture analysis project focused on turning raw traffic into findings that are easy to explain in an interview.

Current status: Phase 3 is live with HTML reporting, scored findings, and a cleaner case-study flow.

### StripSec

Layer 5 placeholder for the final project in this series.

Current status: planned.

## Repo Layout

```text
LAYERxLABS/
|-- NetScope/
|-- SniffCore/
|   |-- docs/
|   |-- src/sniffcore/
|   `-- tests/
|-- StripSec/
`-- reports/
```

## What We Care About

- Clear project scope instead of tool dumping
- Reproducible lab work
- Evidence that can be shown to a reviewer or hiring manager
- Writeups that sound like engineers, not brochure copy

## Ground Rules

Everything in this repo is meant for isolated, permitted lab work. The value here is in analysis, reporting, and understanding what the traffic means, not in trying to turn the repo into an attack launcher.

## Current Focus

`SniffCore` is first up inside this monorepo. The build plan, architecture notes, and milestone breakdown live in [SniffCore/README.md](SniffCore/README.md) and the docs inside `SniffCore/docs/`.
