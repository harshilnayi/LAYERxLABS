from __future__ import annotations

import argparse
import json

from .pipeline import analyze_capture
from .reporting import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stripsec",
        description="Analyze web-session captures for downgrade and HTTPS hygiene issues.",
    )
    parser.add_argument("--input", required=True, help="Path to the structured JSON capture.")
    parser.add_argument("--output-dir", default="reports", help="Directory where reports should be written.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    report = analyze_capture(args.input)
    json_path, markdown_path, html_path = write_reports(report, args.output_dir)

    print(json.dumps(report["overview"], indent=2))
    print(f"JSON report: {json_path.resolve()}")
    print(f"Markdown report: {markdown_path.resolve()}")
    print(f"HTML report: {html_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
