from __future__ import annotations

import argparse
import json

from .pipeline import analyze_capture
from .reporting import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffcore",
        description="Analyze Layer 2 packet captures and turn them into sharable findings.",
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to the .pcap or .pcapng file to analyze.",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory where JSON and Markdown reports should be written.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top talkers to include in the report.",
    )
    parser.add_argument(
        "--baseline-pcap",
        help="Optional known-good capture used for baseline comparison.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    report = analyze_capture(
        args.pcap,
        top_talkers_limit=args.top,
        baseline_capture_path=args.baseline_pcap,
    )
    json_path, markdown_path = write_reports(report, args.output_dir)

    print(json.dumps(report["overview"], indent=2))
    print(f"JSON report: {json_path.resolve()}")
    print(f"Markdown report: {markdown_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
