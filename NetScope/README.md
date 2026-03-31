# NetScope

`NetScope` is the Layer 1 slot inside `LAYERxLABS`.

Right now this folder is intentionally light because the first implementation started outside this repo as `LayerSentinel`. Before we carry that work in here, we want the project story to be solid:

- the scan flow has to match what the docs promise
- the evidence has to be useful, not just dumped to disk
- the repo has to look personal and credible on a resume

## Current Hand-Off Status

- External repo reviewed: `LayerSentinel`
- Review writeup: [../reports/layer1-layersentinel-review.md](../reports/layer1-layersentinel-review.md)
- Next step: fix the live-scan logic, tighten the packaging, and then fold the improved version into `NetScope`

## What NetScope Should Eventually Show

- baseline-aware device tracking
- rogue or unknown host triage
- practical investigation reports
- clear before/after metrics from test scans

This folder will grow once the Layer 1 review feedback is applied.
