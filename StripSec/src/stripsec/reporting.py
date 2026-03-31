from __future__ import annotations

import json
from datetime import UTC, datetime
from html import escape
from pathlib import Path


SEVERITY_COLORS = {
    "high": "#b42318",
    "medium": "#b54708",
    "low": "#0b6e4f",
}


def _render_markdown(report: dict) -> str:
    overview = report["overview"]
    severity_counts = overview["severity_counts"]
    lines = [
        "# StripSec Analysis Report",
        "",
        f"- Capture name: {report['capture']['name']}",
        f"- Source file: `{report['capture']['source']}`",
        f"- Pages analyzed: {overview['pages_analyzed']}",
        f"- Domains seen: {overview['domains_seen']}",
        f"- HTTPS pages: {overview['https_pages']}",
        f"- HTTP pages: {overview['http_pages']}",
        f"- Findings raised: {overview['findings_count']}",
        f"- Risk score: {overview['risk_score']}/100 ({overview['risk_level']})",
        "",
        "## Severity Mix",
        "",
        f"- High: {severity_counts['high']}",
        f"- Medium: {severity_counts['medium']}",
        f"- Low: {severity_counts['low']}",
        "",
        "## Domains",
        "",
    ]

    for domain in report["domains"]:
        lines.append(f"- {domain}")

    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("- No findings were raised.")
    else:
        for finding in report["findings"]:
            lines.extend(
                [
                    f"### {finding['title']}",
                    f"- Category: {finding['category']}",
                    f"- Severity: {finding['severity']}",
                    f"- Score: {finding['score']}",
                    f"- Summary: {finding['summary']}",
                    f"- Recommended action: {finding['recommendation']}",
                    f"- Evidence: `{json.dumps(finding['evidence'], sort_keys=True)}`",
                    "",
                ]
            )

    return "\n".join(lines)


def _render_html(report: dict) -> str:
    overview = report["overview"]
    severity_counts = overview["severity_counts"]
    cards = [
        ("Pages", overview["pages_analyzed"]),
        ("Domains", overview["domains_seen"]),
        ("Findings", overview["findings_count"]),
        ("Risk", f"{overview['risk_score']}/100"),
    ]

    card_html = "\n".join(
        f'<article class="card"><h2>{escape(title)}</h2><p>{escape(str(value))}</p></article>'
        for title, value in cards
    )

    severity_html = "\n".join(
        f'<div class="severity-row"><span>{escape(level.title())}</span><strong>{count}</strong></div>'
        for level, count in severity_counts.items()
    )

    finding_html = "\n".join(
        f"""
        <article class="finding-card" style="border-top: 6px solid {SEVERITY_COLORS[finding['severity']]};">
          <div class="finding-head">
            <span class="badge" style="background:{SEVERITY_COLORS[finding['severity']]};">{escape(finding['severity'].upper())}</span>
            <span class="score">Score {finding['score']}</span>
          </div>
          <h3>{escape(finding['title'])}</h3>
          <p>{escape(finding['summary'])}</p>
          <p><strong>Recommended action:</strong> {escape(finding['recommendation'])}</p>
          <details>
            <summary>Evidence</summary>
            <pre>{escape(json.dumps(finding['evidence'], sort_keys=True, indent=2))}</pre>
          </details>
        </article>
        """
        for finding in report["findings"]
    ) or "<p class='empty'>No findings available.</p>"

    domain_html = "\n".join(f"<li>{escape(domain)}</li>" for domain in report["domains"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>StripSec Report</title>
  <style>
    :root {{
      --bg: #f6efe6;
      --panel: rgba(255, 252, 246, 0.95);
      --ink: #1d2731;
      --muted: #5f6c78;
      --line: #d8cfc4;
      --accent: #9a3412;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Georgia, serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(154, 52, 18, 0.16), transparent 28%),
        linear-gradient(135deg, #efe1d3, var(--bg));
    }}
    main {{ max-width: 1140px; margin: 0 auto; padding: 28px 18px 48px; }}
    .hero {{
      padding: 28px;
      border-radius: 24px;
      color: #fffaf5;
      background: linear-gradient(135deg, rgba(46, 32, 22, 0.96), rgba(154, 52, 18, 0.92));
      box-shadow: 0 28px 70px rgba(29, 39, 49, 0.15);
    }}
    .hero h1 {{ margin: 0 0 8px; font-size: clamp(2rem, 4vw, 3.3rem); }}
    .hero p {{ margin: 8px 0; color: rgba(255, 250, 245, 0.86); max-width: 860px; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin: 24px 0;
    }}
    .card, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: 0 14px 40px rgba(29, 39, 49, 0.08);
    }}
    .card {{ padding: 18px 20px; }}
    .card h2 {{ margin: 0; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.09em; color: var(--muted); }}
    .card p {{ margin: 10px 0 0; font-size: 2rem; font-weight: 700; }}
    .panel {{ padding: 20px; margin-top: 18px; }}
    .severity-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-top: 14px; }}
    .severity-row {{ display: flex; justify-content: space-between; padding: 14px 16px; border-radius: 14px; background: #f5ecdf; }}
    .domains {{ columns: 2; margin: 12px 0 0; padding-left: 18px; }}
    .findings-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-top: 16px; }}
    .finding-card {{ padding: 18px; background: #fffdf9; border-radius: 20px; border: 1px solid var(--line); }}
    .finding-head {{ display: flex; justify-content: space-between; gap: 12px; align-items: center; }}
    .badge {{ display: inline-block; padding: 6px 10px; border-radius: 999px; color: white; font-size: 0.78rem; font-weight: 700; }}
    .score {{ color: var(--muted); font-size: 0.95rem; font-weight: 600; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #f7efe6; border-radius: 14px; padding: 12px; font-size: 0.88rem; }}
    .empty {{ color: var(--muted); }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <p>StripSec Layer 5 Review</p>
      <h1>Transport Security Dashboard</h1>
      <p>This report highlights downgrade paths, insecure cookie handling, missing HTTPS controls, and other web-session hygiene issues from a controlled lab capture.</p>
      <p>Capture: {escape(report['capture']['name'])} | Risk: {overview['risk_score']}/100 ({escape(overview['risk_level'])})</p>
    </section>

    <section class="cards">
      {card_html}
    </section>

    <section class="panel">
      <h2>Severity Mix</h2>
      <div class="severity-grid">
        {severity_html}
      </div>
    </section>

    <section class="panel">
      <h2>Domains Seen</h2>
      <ul class="domains">
        {domain_html}
      </ul>
    </section>

    <section class="panel">
      <h2>Findings</h2>
      <div class="findings-grid">
        {finding_html}
      </div>
    </section>
  </main>
</body>
</html>
"""


def write_reports(report: dict, output_dir: str | Path = "reports") -> tuple[Path, Path, Path]:
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    json_path = target_dir / f"stripsec_report_{timestamp}.json"
    markdown_path = target_dir / f"stripsec_report_{timestamp}.md"
    html_path = target_dir / f"stripsec_report_{timestamp}.html"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    html_path.write_text(_render_html(report), encoding="utf-8")
    return json_path, markdown_path, html_path
