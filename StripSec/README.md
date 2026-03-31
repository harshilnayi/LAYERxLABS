# StripSec

`StripSec` is the Layer 5 project in the `LAYERxLABS` series.

This project is intentionally built on the defensive side. Instead of recreating attack tooling, `StripSec` focuses on transport downgrade risk, HTTPS hygiene, cookie safety, and session handling mistakes inside controlled lab traffic.

That makes it safer, easier to explain, and much stronger for a resume.

## What It Does Right Now

- reads a structured web-session capture from JSON
- flags HTTP downgrade redirects
- flags HTTPS responses that are missing HSTS
- flags session cookies that are missing the `Secure` flag
- flags mixed-content resources on HTTPS pages
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

Run the tests:

```powershell
pytest
```

## Output

Each run writes:

- a JSON report for automation
- a Markdown summary for quick review
- an HTML dashboard for demos and portfolio use

## Project Shape

- `src/stripsec/ingest.py` loads the session capture
- `src/stripsec/detectors.py` raises downgrade and session-hygiene findings
- `src/stripsec/pipeline.py` assembles the final report
- `src/stripsec/reporting.py` writes the report files
- `src/stripsec/cli.py` runs the tool from the command line
- `tests/fixtures/sample_transport_capture.json` is the starter lab fixture

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

## Good Project Story

The story here is not "I ran sslstrip."

The better story is:

> I built a Layer 5 review workflow that spots downgrade paths, insecure session handling, and missing HTTPS controls in captured web traffic, then turns that into a report someone else can act on.
