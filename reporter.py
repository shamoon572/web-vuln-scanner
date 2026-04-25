"""
Report generators.

Produces:
  - JSON report   (machine-readable, suitable for CI/CD integration)
  - HTML report   (clean dashboard with severity cards, findings table, charts)
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from core.models  import ScanResult, Finding, Severity
from core.logger  import setup_logger

log = setup_logger("reporter")


# ─────────────────────────────────────────────────────────────────────────────
# JSON Reporter
# ─────────────────────────────────────────────────────────────────────────────

class JSONReporter:
    def __init__(self, output_dir: str) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, result: ScanResult) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = self.output_dir / f"scan_report_{timestamp}.json"

        report = {
            "scanner":  "WebVulnScanner v1.0",
            "summary":  result.summary(),
            "findings": [f.to_dict() for f in result.findings],
            "oob_hits": result.errors,   # repurposed field for OOB hits
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

        log.info("JSON report saved → %s", path)
        return str(path)


# ─────────────────────────────────────────────────────────────────────────────
# HTML Reporter
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "Critical":      "#dc2626",
    "High":          "#ea580c",
    "Medium":        "#d97706",
    "Low":           "#2563eb",
    "Informational": "#6b7280",
}

_SEVERITY_BG = {
    "Critical":      "#fef2f2",
    "High":          "#fff7ed",
    "Medium":        "#fffbeb",
    "Low":           "#eff6ff",
    "Informational": "#f9fafb",
}


class HTMLReporter:
    def __init__(self, output_dir: str) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, result: ScanResult) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = self.output_dir / f"scan_report_{timestamp}.html"

        html = self._build_html(result)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)

        log.info("HTML report saved → %s", path)
        return str(path)

    def _build_html(self, result: ScanResult) -> str:
        summary = result.summary()
        findings_by_sev: dict[str, list[Finding]] = {}
        for f in result.findings:
            findings_by_sev.setdefault(f.severity.value, []).append(f)

        severity_order = ["Critical", "High", "Medium", "Low", "Informational"]

        # ── Summary cards ─────────────────────────────────────────────────────
        cards_html = ""
        for sev in severity_order:
            count = summary["by_severity"].get(sev, 0)
            color = _SEVERITY_COLORS.get(sev, "#6b7280")
            cards_html += f"""
            <div class="card" style="border-top:4px solid {color}">
                <div class="card-count" style="color:{color}">{count}</div>
                <div class="card-label">{sev}</div>
            </div>"""

        # ── Findings table rows ────────────────────────────────────────────────
        rows_html = ""
        for sev in severity_order:
            for f in findings_by_sev.get(sev, []):
                color  = _SEVERITY_COLORS.get(sev, "#6b7280")
                bg     = _SEVERITY_BG.get(sev, "#f9fafb")
                esc_url     = _he(f.url)
                esc_param   = _he(f.parameter)
                esc_payload = _he(f.payload[:80])
                esc_evidence= _he(f.evidence[:150])
                esc_type    = _he(f.vuln_type.value)
                conf_pct    = int(f.confidence * 100)
                rows_html += f"""
                <tr style="background:{bg}">
                    <td><span class="badge" style="background:{color}">{sev}</span></td>
                    <td class="vuln-type">{esc_type}</td>
                    <td class="url-cell" title="{esc_url}">{esc_url[:60]}{'…' if len(f.url)>60 else ''}</td>
                    <td><code>{esc_param}</code></td>
                    <td><code class="payload">{esc_payload}</code></td>
                    <td>
                        <div class="conf-bar-wrap">
                            <div class="conf-bar" style="width:{conf_pct}%;background:{color}"></div>
                        </div>
                        <span class="conf-label">{conf_pct}%</span>
                    </td>
                    <td class="evidence-cell">{esc_evidence}</td>
                </tr>
                <tr class="detail-row">
                    <td colspan="7">
                        <div class="detail-box">
                            <strong>Description:</strong> {_he(f.description)}<br>
                            <strong>Remediation:</strong> {_he(f.remediation)}<br>
                            <strong>Method:</strong> {_he(f.method)} &nbsp;|&nbsp;
                            <strong>Timestamp:</strong> {_he(f.timestamp)}
                        </div>
                    </td>
                </tr>"""

        # ── Chart data ────────────────────────────────────────────────────────
        chart_labels = json.dumps([s for s in severity_order if s in summary["by_severity"]])
        chart_data   = json.dumps([summary["by_severity"].get(s, 0) for s in severity_order if s in summary["by_severity"]])
        chart_colors = json.dumps([_SEVERITY_COLORS.get(s, "#6b7280") for s in severity_order if s in summary["by_severity"]])

        # ── Vuln type breakdown ───────────────────────────────────────────────
        type_counts: dict[str, int] = {}
        for f in result.findings:
            type_counts[f.vuln_type.value] = type_counts.get(f.vuln_type.value, 0) + 1
        type_labels = json.dumps(list(type_counts.keys()))
        type_data   = json.dumps(list(type_counts.values()))

        no_findings_msg = ""
        if not result.findings:
            no_findings_msg = '<tr><td colspan="7" style="text-align:center;padding:2rem;color:#6b7280">No vulnerabilities found.</td></tr>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebVulnScanner Report — {_he(result.target)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #263044;
    --text: #e2e8f0; --text2: #94a3b8; --border: #334155;
    --accent: #38bdf8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }}
  header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); padding: 2rem 3rem; border-bottom: 1px solid var(--border); }}
  header h1 {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }}
  header p {{ color: var(--text2); margin-top: 0.3rem; font-size: 0.9rem; }}
  .main {{ padding: 2rem 3rem; max-width: 1600px; margin: 0 auto; }}
  .section-title {{ font-size: 1.1rem; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 1px; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-box {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
  .stat-lbl {{ font-size: 0.8rem; color: var(--text2); margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.5px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; text-align: center; transition: transform .2s; }}
  .card:hover {{ transform: translateY(-3px); }}
  .card-count {{ font-size: 2.2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.8rem; color: var(--text2); margin-top: 0.3rem; }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
  .chart-box {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; }}
  .chart-box h3 {{ font-size: 0.9rem; color: var(--text2); margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }}
  thead {{ background: var(--surface2); }}
  th {{ padding: 0.85rem 1rem; text-align: left; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text2); }}
  td {{ padding: 0.75rem 1rem; font-size: 0.85rem; border-top: 1px solid var(--border); vertical-align: top; color: #cbd5e1; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); cursor: pointer; }}
  .detail-row td {{ padding: 0; }}
  .detail-box {{ background: var(--surface2); border-top: 1px dashed var(--border); padding: 0.75rem 1rem; font-size: 0.82rem; color: var(--text2); display: none; line-height: 1.6; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.72rem; font-weight: 600; color: #fff; letter-spacing: 0.3px; }}
  .vuln-type {{ font-weight: 600; color: var(--text); }}
  .url-cell {{ font-size: 0.78rem; color: var(--accent); font-family: monospace; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  code {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.78rem; }}
  .payload {{ color: #f87171; }}
  .evidence-cell {{ font-size: 0.75rem; color: var(--text2); max-width: 200px; }}
  .conf-bar-wrap {{ background: var(--border); border-radius: 999px; height: 6px; width: 80px; margin-bottom: 3px; }}
  .conf-bar {{ height: 6px; border-radius: 999px; }}
  .conf-label {{ font-size: 0.75rem; color: var(--text2); }}
  footer {{ text-align: center; padding: 2rem; color: var(--text2); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 3rem; }}
  @media (max-width: 768px) {{ .charts {{ grid-template-columns: 1fr; }} .main {{ padding: 1rem; }} }}
</style>
</head>
<body>
<header>
  <h1>🔍 WebVulnScanner Security Report</h1>
  <p>Target: <strong>{_he(result.target)}</strong> &nbsp;|&nbsp;
     Scan started: {_he(result.start_time)} &nbsp;|&nbsp;
     Completed: {_he(result.end_time or 'N/A')}</p>
</header>

<div class="main">

  <div class="section-title">Scan Statistics</div>
  <div class="stat-grid">
    <div class="stat-box"><div class="stat-num">{summary['urls_crawled']}</div><div class="stat-lbl">URLs Crawled</div></div>
    <div class="stat-box"><div class="stat-num">{summary['requests_made']}</div><div class="stat-lbl">Requests Sent</div></div>
    <div class="stat-box"><div class="stat-num">{summary['total_findings']}</div><div class="stat-lbl">Total Findings</div></div>
    <div class="stat-box"><div class="stat-num">{len(type_counts)}</div><div class="stat-lbl">Vuln Types</div></div>
  </div>

  <div class="section-title">Findings by Severity</div>
  <div class="cards">
    {cards_html}
  </div>

  <div class="charts">
    <div class="chart-box">
      <h3>Severity Distribution</h3>
      <canvas id="sevChart" height="160"></canvas>
    </div>
    <div class="chart-box">
      <h3>Vulnerability Types</h3>
      <canvas id="typeChart" height="160"></canvas>
    </div>
  </div>

  <div class="section-title">Vulnerability Findings</div>
  <table id="findingsTable">
    <thead>
      <tr>
        <th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th>
        <th>Payload</th><th>Confidence</th><th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      {rows_html or no_findings_msg}
    </tbody>
  </table>

</div>

<footer>
  Generated by <strong>WebVulnScanner v1.0</strong> — For authorised security testing only.<br>
  Report generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
</footer>

<script>
// Toggle detail rows
document.querySelectorAll('#findingsTable tbody tr:not(.detail-row)').forEach((row, i) => {{
  row.addEventListener('click', () => {{
    const next = row.nextElementSibling;
    if (next && next.classList.contains('detail-row')) {{
      const box = next.querySelector('.detail-box');
      box.style.display = box.style.display === 'block' ? 'none' : 'block';
    }}
  }});
}});

// Severity doughnut chart
const sevCtx = document.getElementById('sevChart');
if (sevCtx) {{
  new Chart(sevCtx, {{
    type: 'doughnut',
    data: {{ labels: {chart_labels}, datasets: [{{ data: {chart_data}, backgroundColor: {chart_colors}, borderWidth: 2, borderColor: '#1e293b' }}] }},
    options: {{ plugins: {{ legend: {{ position: 'right', labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }}, cutout: '60%' }}
  }});
}}

// Type bar chart
const typeCtx = document.getElementById('typeChart');
if (typeCtx) {{
  new Chart(typeCtx, {{
    type: 'bar',
    data: {{
      labels: {type_labels},
      datasets: [{{ data: {type_data}, backgroundColor: '#38bdf8', borderRadius: 5, borderSkipped: false }}]
    }},
    options: {{
      indexAxis: 'y',
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#334155' }} }},
        y: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }}
      }}
    }}
  }});
}}
</script>
</body>
</html>"""


def _he(text: str) -> str:
    """HTML-escape a string."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))
