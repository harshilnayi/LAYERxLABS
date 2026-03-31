from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def _render_markdown(report: dict) -> str:
    capture = report["capture"]
    overview = report["overview"]
    lines = [
        "# SniffCore Phase 1 Report",
        "",
        f"- Capture file: `{capture['source']}`",
        f"- Frames processed: {overview['total_frames']}",
        f"- Unique source MACs: {overview['unique_source_macs']}",
        f"- Broadcast frames: {overview['broadcast_frames']}",
        f"- Findings raised: {overview['findings_count']}",
        "",
        "## Protocol Mix",
        "",
    ]

    for protocol, count in report["protocols"].items():
        lines.append(f"- {protocol}: {count}")

    lines.extend(["", "## Top Talkers", ""])
    for index, host in enumerate(report["top_talkers"], start=1):
        ips = ", ".join(host["ips"]) if host["ips"] else "No IPs observed"
        lines.extend(
            [
                f"### Host {index}",
                f"- MAC: {host['mac']}",
                f"- IPs: {ips}",
                f"- Frames sent: {host['frames_sent']}",
                f"- Bytes sent: {host['bytes_sent']}",
                f"- Broadcast frames sent: {host['broadcast_frames_sent']}",
                "",
            ]
        )

    lines.extend(["## Findings", ""])
    if not report["findings"]:
        lines.append("- No phase 1 findings were raised.")
    else:
        for finding in report["findings"]:
            lines.extend(
                [
                    f"### {finding['title']}",
                    f"- Category: {finding['category']}",
                    f"- Severity: {finding['severity']}",
                    f"- Summary: {finding['summary']}",
                    f"- Evidence: `{json.dumps(finding['evidence'], sort_keys=True)}`",
                    "",
                ]
            )

    return "\n".join(lines)


def write_reports(report: dict, output_dir: str | Path = "reports") -> tuple[Path, Path]:
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    json_path = target_dir / f"sniffcore_report_{timestamp}.json"
    markdown_path = target_dir / f"sniffcore_report_{timestamp}.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return json_path, markdown_path
