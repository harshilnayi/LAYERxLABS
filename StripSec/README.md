# StripSec

`StripSec` is the Layer 5 project in the `LAYERxLABS` series.

This project stays on the defensive side. Instead of trying to recreate session-hijack tooling, `StripSec` reviews captured web traffic from a controlled lab and points out the places where transport security or session handling breaks down.

The goal is to make the interesting parts visible fast: downgrade paths, weak HTTPS posture, cookie handling mistakes, and browser-side policy gaps.

## What It Does Right Now

- reads either a structured JSON capture or a browser-exported HAR file
- flags HTTP downgrade redirects
- flags sensitive form submissions that happen over HTTP
- flags sensitive values that show up in query strings
- flags HTTPS responses that are missing HSTS
- flags session cookies that are missing the `Secure` flag
- flags cookies that are missing `HttpOnly` or `SameSite`
- flags mixed-content resources on HTTPS pages
- flags missing browser protection headers like CSP and Referrer-Policy
- assigns severity scores and recommended next actions
- writes JSON, Markdown, and HTML reports

## Quick Start

Install it locally:

```powershell
python -m pip install -e .
```

Run the sample analysis:

```powershell
python -m stripsec --input .\tests\fixtures\sample_transport_capture.json --output-dir .\reports
```

Run the HAR sample:

```powershell
python -m stripsec --input .\tests\fixtures\sample_browser_export.har --output-dir .\reports
```

Run the tests:

```powershell
pytest
```

## Output

Each run writes:

- a JSON report for automation
- a Markdown summary for quick review
- an HTML dashboard for easier review

Each report includes:

- a short risk summary with severity counts
- a protection summary for HSTS, CSP, Referrer-Policy, and session-cookie coverage
- downgrade-path evidence when redirects push traffic toward HTTP
- recommendation text tied to each finding

## Project Shape

- `src/stripsec/ingest.py` loads either structured JSON captures or HAR exports
- `src/stripsec/detectors.py` raises downgrade, session, and browser-policy findings
- `src/stripsec/pipeline.py` assembles the final report
- `src/stripsec/reporting.py` writes the report files
- `src/stripsec/cli.py` runs the tool from the command line
- `tests/fixtures/` holds both noisy and cleaner lab captures

## How To Start It Any Time

From the repo root:

```powershell
cd .\StripSec
python -m pip install -e .
python -m stripsec --input .\tests\fixtures\sample_transport_capture.json --output-dir .\reports
```

If it is already installed in editable mode, you only need:

```powershell
cd .\StripSec
python -m stripsec --input .\tests\fixtures\sample_transport_capture.json --output-dir .\reports
```

## Sample Inputs

- `tests/fixtures/sample_transport_capture.json` is a hand-shaped lab capture with several clear problems
- `tests/fixtures/sample_browser_export.har` shows the same kind of review flow on browser-exported traffic
- `tests/fixtures/clean_hardened_capture.json` is a quieter reference case that should stay clean

## Why This Shape Works

`StripSec` is meant to answer a simple question: if someone hands over a captured web session, can we quickly tell whether transport and session safety are holding up?

That keeps the project grounded in analysis, evidence, and repeatable lab work instead of reducing it to a thin wrapper around one legacy tool.
