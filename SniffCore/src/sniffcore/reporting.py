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
    capture = report["capture"]
    overview = report["overview"]
    severity_counts = overview["severity_counts"]
    lines = [
        "# SniffCore Analysis Report",
        "",
        f"- Capture file: `{capture['source']}`",
        f"- Baseline file: `{capture['baseline_source']}`" if capture["baseline_source"] else "- Baseline file: None",
        f"- Frames processed: {overview['total_frames']}",
        f"- Unique source MACs: {overview['unique_source_macs']}",
        f"- Broadcast frames: {overview['broadcast_frames']}",
        f"- Findings raised: {overview['findings_count']}",
        f"- Risk score: {overview['risk_score']}/100 ({overview['risk_level']})",
        "",
        "## Severity Mix",
        "",
        f"- High: {severity_counts['high']}",
        f"- Medium: {severity_counts['medium']}",
        f"- Low: {severity_counts['low']}",
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

    if report.get("baseline_comparison"):
        comparison = report["baseline_comparison"]
        lines.extend(
            [
                "## Baseline Comparison",
                "",
                f"- New source MACs: {', '.join(comparison['new_source_macs']) or 'None'}",
                f"- New protocols: {', '.join(comparison['new_protocols']) or 'None'}",
                f"- New DHCP servers: {', '.join(comparison['new_dhcp_servers']) or 'None'}",
                f"- New STP senders: {', '.join(comparison['new_stp_senders']) or 'None'}",
                "",
            ]
        )

    lines.extend(["## Findings", ""])
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


def _render_bar_rows(items: dict[str, int], palette: dict[str, str]) -> str:
    if not items:
        return "<p class='empty'>No data available.</p>"

    max_value = max(items.values()) or 1
    rows = []
    for label, value in items.items():
        width = max(8, int((value / max_value) * 100)) if value else 0
        color = palette.get(label.lower(), "#1f2937")
        rows.append(
            f"""
            <div class="bar-row">
              <div class="bar-label">{escape(label)}</div>
              <div class="bar-track"><span class="bar-fill" style="width:{width}%; background:{escape(color)};"></span></div>
              <div class="bar-value">{value}</div>
            </div>
            """
        )
    return "\n".join(rows)


def _render_html(report: dict) -> str:
    capture = report["capture"]
    overview = report["overview"]
    baseline = report.get("baseline_comparison")
    severity_counts = overview["severity_counts"]

    protocol_chart = _render_bar_rows(report["protocols"], {})
    severity_chart = _render_bar_rows(
        {
            "High": severity_counts["high"],
            "Medium": severity_counts["medium"],
            "Low": severity_counts["low"],
        },
        {"high": SEVERITY_COLORS["high"], "medium": SEVERITY_COLORS["medium"], "low": SEVERITY_COLORS["low"]},
    )

    finding_cards = []
    for finding in report["findings"]:
        color = SEVERITY_COLORS.get(finding["severity"], "#1f2937")
        evidence = escape(json.dumps(finding["evidence"], sort_keys=True, indent=2))
        finding_cards.append(
            f"""
            <article class="finding-card" style="border-top: 6px solid {escape(color)};">
              <div class="finding-meta">
                <span class="badge" style="background:{escape(color)};">{escape(finding['severity'].upper())}</span>
                <span class="score">Score {finding['score']}</span>
              </div>
              <h3>{escape(finding['title'])}</h3>
              <p class="summary">{escape(finding['summary'])}</p>
              <p class="action"><strong>Recommended action:</strong> {escape(finding['recommendation'])}</p>
              <details>
                <summary>Evidence</summary>
                <pre>{evidence}</pre>
              </details>
            </article>
            """
        )

    top_talker_rows = []
    for host in report["top_talkers"]:
        ips = ", ".join(host["ips"]) if host["ips"] else "No IPs observed"
        top_talker_rows.append(
            f"""
            <tr>
              <td>{escape(host['mac'])}</td>
              <td>{escape(ips)}</td>
              <td>{host['frames_sent']}</td>
              <td>{host['bytes_sent']}</td>
              <td>{host['broadcast_frames_sent']}</td>
            </tr>
            """
        )

    baseline_html = ""
    if baseline:
        baseline_html = f"""
        <section class="panel">
          <div class="panel-header">
            <h2>Baseline Comparison</h2>
            <p>Quick drift view against the known-good capture.</p>
          </div>
          <div class="comparison-grid">
            <div>
              <h3>New Source MACs</h3>
              <p>{escape(', '.join(baseline['new_source_macs']) or 'None')}</p>
            </div>
            <div>
              <h3>New DHCP Servers</h3>
              <p>{escape(', '.join(baseline['new_dhcp_servers']) or 'None')}</p>
            </div>
            <div>
              <h3>New STP Senders</h3>
              <p>{escape(', '.join(baseline['new_stp_senders']) or 'None')}</p>
            </div>
            <div>
              <h3>New Protocols</h3>
              <p>{escape(', '.join(baseline['new_protocols']) or 'None')}</p>
            </div>
          </div>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SniffCore Report</title>
  <style>
    :root {{
      --bg: #f5efe5;
      --panel: rgba(255, 251, 245, 0.94);
      --ink: #18212b;
      --muted: #53606d;
      --line: #d8cfc2;
      --teal: #114b5f;
      --sand: #eadbc8;
      --accent: #c8553d;
      --high: {SEVERITY_COLORS['high']};
      --medium: {SEVERITY_COLORS['medium']};
      --low: {SEVERITY_COLORS['low']};
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Georgia, serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(17, 75, 95, 0.16), transparent 30%),
        linear-gradient(135deg, #efe4d3, var(--bg));
    }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px 18px 48px; }}
    .hero {{
      background: linear-gradient(135deg, rgba(17, 75, 95, 0.98), rgba(61, 34, 28, 0.9));
      color: #fffaf3;
      border-radius: 24px;
      padding: 28px;
      box-shadow: 0 28px 70px rgba(24, 33, 43, 0.16);
    }}
    .hero h1 {{ margin: 0 0 8px; font-size: clamp(2rem, 4vw, 3.3rem); }}
    .hero p {{ margin: 8px 0; color: rgba(255, 250, 243, 0.86); max-width: 900px; }}
    .hero-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 18px;
      margin-top: 16px;
      font-size: 0.95rem;
    }}
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
      box-shadow: 0 14px 40px rgba(24, 33, 43, 0.08);
    }}
    .card {{
      padding: 18px 20px;
    }}
    .card h2 {{
      margin: 0;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.09em;
      color: var(--muted);
    }}
    .card p {{
      margin: 10px 0 0;
      font-size: 2rem;
      font-weight: 700;
    }}
    .risk-note {{ font-size: 0.95rem; color: var(--muted); margin-top: 8px; }}
    .panel {{ padding: 20px; margin-top: 18px; }}
    .panel-header h2 {{ margin: 0 0 8px; }}
    .panel-header p {{ margin: 0; color: var(--muted); }}
    .chart-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
      margin-top: 18px;
    }}
    .bar-row {{
      display: grid;
      grid-template-columns: 110px 1fr 44px;
      gap: 12px;
      align-items: center;
      margin: 12px 0;
    }}
    .bar-label {{ font-weight: 600; }}
    .bar-track {{
      width: 100%;
      height: 12px;
      background: #ece2d6;
      border-radius: 999px;
      overflow: hidden;
    }}
    .bar-fill {{
      display: block;
      height: 100%;
      border-radius: 999px;
    }}
    .bar-value {{ text-align: right; color: var(--muted); font-size: 0.92rem; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
    }}
    th, td {{
      text-align: left;
      padding: 12px 10px;
      border-bottom: 1px solid #eadfce;
      vertical-align: top;
    }}
    th {{
      font-size: 0.84rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
    }}
    .comparison-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-top: 16px;
    }}
    .comparison-grid h3 {{
      margin: 0 0 6px;
      font-size: 1rem;
    }}
    .comparison-grid p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }}
    .findings-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
      margin-top: 18px;
    }}
    .finding-card {{
      padding: 18px;
      background: #fffdf9;
      border-radius: 20px;
      border: 1px solid var(--line);
    }}
    .finding-card h3 {{ margin: 12px 0 8px; font-size: 1.2rem; }}
    .finding-meta {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
    }}
    .badge {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      color: white;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }}
    .score {{
      color: var(--muted);
      font-size: 0.95rem;
      font-weight: 600;
    }}
    .summary, .action {{
      color: var(--ink);
      line-height: 1.6;
    }}
    details {{
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px dashed var(--line);
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #f7f0e7;
      border-radius: 14px;
      padding: 12px;
      font-size: 0.88rem;
    }}
    .empty {{ color: var(--muted); }}
    @media (max-width: 720px) {{
      .hero {{ padding: 22px; }}
      .bar-row {{ grid-template-columns: 86px 1fr 36px; gap: 8px; }}
      th:nth-child(4), td:nth-child(4) {{ display: none; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <p>SniffCore Layer 2 Review</p>
      <h1>Capture Analysis Dashboard</h1>
      <p>This report turns a lab packet capture into a readable triage view. It highlights where the capture drifted, how severe the findings look, and what to validate next.</p>
      <div class="hero-meta">
        <span>Capture: {escape(capture['source'])}</span>
        <span>Baseline: {escape(capture['baseline_source'] or 'None')}</span>
        <span>Risk: {overview['risk_score']}/100 ({escape(overview['risk_level'])})</span>
      </div>
    </section>

    <section class="cards">
      <article class="card"><h2>Frames</h2><p>{overview['total_frames']}</p></article>
      <article class="card"><h2>Source MACs</h2><p>{overview['unique_source_macs']}</p></article>
      <article class="card"><h2>Broadcast Frames</h2><p>{overview['broadcast_frames']}</p></article>
      <article class="card"><h2>Findings</h2><p>{overview['findings_count']}</p><div class="risk-note">High {severity_counts['high']} | Medium {severity_counts['medium']} | Low {severity_counts['low']}</div></article>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2>Signal Overview</h2>
        <p>Two quick charts to show protocol mix and severity spread without opening the raw JSON.</p>
      </div>
      <div class="chart-grid">
        <div>
          <h3>Protocol Mix</h3>
          {protocol_chart}
        </div>
        <div>
          <h3>Severity Mix</h3>
          {severity_chart}
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2>Top Talkers</h2>
        <p>The busiest senders in the capture, useful for picking where to look first.</p>
      </div>
      <table>
        <thead>
          <tr>
            <th>MAC</th>
            <th>IPs</th>
            <th>Frames Sent</th>
            <th>Bytes Sent</th>
            <th>Broadcast Sent</th>
          </tr>
        </thead>
        <tbody>
          {''.join(top_talker_rows) or "<tr><td colspan='5'>No talkers found.</td></tr>"}
        </tbody>
      </table>
    </section>

    {baseline_html}

    <section class="panel">
      <div class="panel-header">
        <h2>Findings</h2>
        <p>Each card includes severity, score, a plain-language summary, and a recommended analyst action.</p>
      </div>
      <div class="findings-grid">
        {''.join(finding_cards) or "<p class='empty'>No findings available.</p>"}
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

    json_path = target_dir / f"sniffcore_report_{timestamp}.json"
    markdown_path = target_dir / f"sniffcore_report_{timestamp}.md"
    html_path = target_dir / f"sniffcore_report_{timestamp}.html"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    html_path.write_text(_render_html(report), encoding="utf-8")
    return json_path, markdown_path, html_path
