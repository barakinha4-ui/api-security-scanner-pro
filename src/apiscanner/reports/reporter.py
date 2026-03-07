"""
reports/reporter.py — JSON / HTML / Markdown Report Generator
Professional security audit reports with full finding detail.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from html import escape
from typing import List

from core.models import ScanResult, Finding, Severity


# ─── JSON ─────────────────────────────────────────────────────────────────────

from core.crypto import shield

class JSONReporter:
    def generate(self, result: ScanResult, path: str, encrypt: bool = False) -> str:
        data = result.to_dict()
        if encrypt:
            data = {"encrypted": True, "payload": shield.encrypt(json.dumps(data, default=str))}
            
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return path


# ─── MARKDOWN ─────────────────────────────────────────────────────────────────

class MarkdownReporter:
    def generate(self, result: ScanResult, path: str) -> str:
        md = self._build(result)
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return path

    def _build(self, result: ScanResult) -> str:
        s = result.summary
        lines: List[str] = []

        lines += [
            "# 🔐 API Security Audit Report",
            "",
            f"> **Target:** `{result.target}`  ",
            f"> **Date:** {result.start_time[:19].replace('T', ' ')} UTC  ",
            f"> **Duration:** {result.duration_seconds:.1f}s  ",
            f"> **Requests made:** {result.total_requests}  ",
            f"> **Scanner version:** {result.scanner_version}  ",
            "",
            "> ⚠️ **This report was generated for authorized security testing only.**",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Security Score | **{s['security_score']}/100 (Rating: {s['security_rating']})** |",
            f"| Total Findings | **{s['total']}** |",
            f"| Confirmed | {s['confirmed_count']} |",
            f"| 🔴 Critical | {s['by_severity'].get('CRITICAL', 0)} |",
            f"| 🟠 High     | {s['by_severity'].get('HIGH', 0)} |",
            f"| 🟡 Medium   | {s['by_severity'].get('MEDIUM', 0)} |",
            f"| 🔵 Low      | {s['by_severity'].get('LOW', 0)} |",
            f"| ⚪ Info     | {s['by_severity'].get('INFO', 0)} |",
            f"| Highest CVSS | **{s['highest_cvss']}** |",
            f"| WAF Detected | {s.get('waf_detected') or 'None'} |",
            f"| Technologies | {', '.join(s.get('technologies', [])) or 'Unknown'} |",
            f"| Endpoints Found | {s['endpoints_found']} |",
            "",
            "---",
            "",
        ]

        # Score visualisation
        score = s["security_score"]
        filled = int(score / 5)
        bar = "█" * filled + "░" * (20 - filled)
        rating = s["security_rating"]
        lines += [
            "## 🎯 Security Score",
            "",
            "```",
            f"Score : {score:3d}/100  [{bar}]  Rating: {rating}",
            "```",
            "",
            "---",
            "",
        ]

        # Findings
        lines += ["## 🔍 Findings", ""]
        by_sev = result.by_severity()

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev_list = by_sev.get(sev, [])
            if not sev_list:
                continue
            emoji = Severity(sev).emoji
            lines += [f"### {emoji} {sev} — {len(sev_list)} finding(s)", ""]

            for i, f in enumerate(sev_list, 1):
                conf = "✅ Confirmed" if f.confirmed else "⚠️ Unconfirmed"
                lines += [
                    f"#### {i}. {f.title}",
                    "",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| ID | `{f.id}` |",
                    f"| Type | {f.vuln_type} |",
                    f"| Endpoint | `{f.endpoint}` |",
                    f"| Method | `{f.method}` |",
                    f"| Parameter | {f.parameter or '—'} |",
                    f"| CVSS | **{f.cvss_score}** |",
                    f"| Vector | `{f.cvss_vector}` |",
                    f"| OWASP | {f.owasp_category} |",
                    f"| Status | {conf} |",
                    f"| Response Time | {f.response_time_ms:.0f}ms |",
                    "",
                ]

                if f.payload and f.payload not in ("N/A", ""):
                    lines += ["**Payload used:**", f"```", f.payload[:400], "```", ""]

                lines += [f"**Description:** {f.description}", ""]

                lines += ["**Recommendation:**", ""]
                for line in f.recommendation.split("\n"):
                    line = line.strip()
                    if line:
                        lines.append(f"- {line.lstrip('0123456789. ')}")
                lines.append("")

                if f.response_body:
                    lines += [
                        "<details><summary>Server Response</summary>",
                        "",
                        "```",
                        f.truncate_response(400),
                        "```",
                        "",
                        "</details>",
                        "",
                    ]

                if f.references:
                    for ref in f.references:
                        lines.append(f"- 📎 {ref}")
                    lines.append("")

                lines += ["---", ""]

        # Footer
        lines += [
            "## 📚 References",
            "",
            "- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)",
            "- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)",
            "- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)",
            "- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)",
            "",
            "---",
            "*Report generated by API Security Scanner v2.0 — Authorized use only.*",
        ]

        return "\n".join(lines)


# ─── HTML ─────────────────────────────────────────────────────────────────────

class HTMLReporter:

    _SEV_STYLE = {
        "CRITICAL": ("#dc2626", "#fef2f2"),
        "HIGH":     ("#ea580c", "#fff7ed"),
        "MEDIUM":   ("#d97706", "#fffbeb"),
        "LOW":      ("#2563eb", "#eff6ff"),
        "INFO":     ("#6b7280", "#f9fafb"),
    }

    def generate(self, result: ScanResult, path: str) -> str:
        html = self._build(result)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _build(self, result: ScanResult) -> str:
        s = result.summary
        score = s["security_score"]
        score_col = "#16a34a" if score >= 75 else ("#d97706" if score >= 50 else "#dc2626")
        findings_html = self._findings_section(result)
        summary_cards = self._summary_cards(s)
        tech_badges   = "".join(
            f'<span class="badge tech">{escape(t)}</span>'
            for t in s.get("technologies", [])
        )
        waf_banner = (
            f'<div class="waf-banner">🛡 WAF detected: <strong>{escape(result.waf_detected)}</strong> '
            f'({result.waf_confidence:.0f}% confidence)</div>'
        ) if result.waf_detected else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Security Report — {escape(result.target)}</title>
<style>
:root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--primary:#1e40af}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.6}}
.header{{background:linear-gradient(135deg,#1e3a8a,#1e40af 50%,#3b82f6);color:#fff;padding:40px 48px}}
.header h1{{font-size:2rem;font-weight:700;margin-bottom:8px}}
.header .meta{{opacity:.85;font-size:.875rem;display:flex;gap:20px;flex-wrap:wrap;margin-top:8px}}
.container{{max-width:1300px;margin:0 auto;padding:32px 24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:16px;margin-bottom:28px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.07)}}
.card .lbl{{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:6px}}
.card .val{{font-size:1.9rem;font-weight:700}}
.score-card{{background:linear-gradient(135deg,#1e3a8a,#3b82f6);color:#fff}}
.score-card .lbl{{color:rgba(255,255,255,.7)}}
.score-bar{{background:rgba(255,255,255,.2);border-radius:999px;height:8px;margin-top:10px;overflow:hidden}}
.score-fill{{height:100%;border-radius:999px;background:#fff}}
section{{margin-bottom:32px}}
section h2{{font-size:1.2rem;font-weight:700;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid var(--border)}}
.finding{{background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:14px;overflow:hidden}}
.fhdr{{padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:10px;user-select:none}}
.fhdr:hover{{filter:brightness(.97)}}
.badge{{padding:2px 9px;border-radius:999px;font-size:.65rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase}}
.fbody{{padding:20px;border-top:1px solid var(--border);display:none}}
.fbody.open{{display:block}}
.ftitle{{font-weight:600;flex:1;font-size:.95rem}}
.cvss-tag{{background:#f1f5f9;color:var(--muted);padding:2px 7px;border-radius:6px;font-size:.72rem;font-family:monospace}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{text-align:left;padding:7px 12px;background:#f1f5f9;font-weight:600;font-size:.7rem;text-transform:uppercase;color:var(--muted)}}
td{{padding:7px 12px;border-top:1px solid var(--border);vertical-align:top}}
td:first-child{{font-weight:500;color:var(--muted);width:130px;white-space:nowrap}}
pre{{background:#0f172a;color:#94a3b8;padding:14px;border-radius:8px;overflow-x:auto;font-size:.78rem;margin-top:10px;white-space:pre-wrap;word-break:break-all}}
.rec{{background:#f0fdf4;border-left:3px solid #16a34a;padding:12px 15px;border-radius:0 8px 8px 0;font-size:.85rem;margin-top:10px}}
.desc{{font-size:.875rem;color:var(--muted);line-height:1.65;margin-bottom:10px}}
.waf-banner{{background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;padding:12px 16px;margin-bottom:22px;font-size:.875rem}}
.tech{{background:#dbeafe;color:#1d4ed8;margin:2px}}
.conf{{color:#16a34a;font-size:.72rem;font-weight:600}}
.unconf{{color:#d97706;font-size:.72rem;font-weight:600}}
.toggle{{margin-left:auto;font-size:.8rem}}
footer{{text-align:center;padding:28px;color:var(--muted);font-size:.78rem;border-top:1px solid var(--border);margin-top:24px}}
.charts-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin-bottom:30px}}
.chart-container{{background:#fff;border:1px solid var(--border);border-radius:12px;padding:15px;height:260px;display:flex;flex-direction:column;align-items:center}}
.chart-container h3{{font-size:.75rem;text-transform:uppercase;color:var(--muted);margin-bottom:10px;align-self:flex-start}}
@media(max-width:640px){{.header{{padding:24px 16px}}.container{{padding:16px}}.charts-grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 API Security Audit Report</h1>
  <div class="meta">
    <span>🎯 <strong>{escape(result.target)}</strong></span>
    <span>📅 {result.start_time[:19].replace("T"," ")} UTC</span>
    <span>⏱ {result.duration_seconds:.1f}s</span>
    <span>📡 {result.total_requests} requests</span>
    <span>🔌 v{result.scanner_version}</span>
  </div>
</div>
<div class="container">
  {waf_banner}
  <div class="grid">
    <div class="card score-card">
      <div class="lbl">Security Score</div>
      <div class="val">{score}/100</div>
      <div class="score-bar"><div class="score-fill" style="width:{score}%"></div></div>
      <div style="margin-top:7px;font-size:.8rem;opacity:.8">Rating: {s['security_rating']}</div>
    </div>
    {summary_cards}
  </div>
  
  <div class="charts-grid">
    <div class="chart-container">
      <h3>Findings by Severity</h3>
      <canvas id="severityChart"></canvas>
    </div>
    <div class="chart-container">
      <h3>Findings by Confidence</h3>
      <canvas id="confidenceChart"></canvas>
    </div>
    <div class="chart-container">
      <h3>OWASP Top 10 Coverage</h3>
      <canvas id="owaspChart"></canvas>
    </div>
  </div>

  {"<div class='card' style='margin-bottom:24px'><div class='lbl'>Technologies detected</div><div style='margin-top:8px'>" + tech_badges + "</div></div>" if tech_badges else ""}
  <section>
    <h2>🔍 Findings ({s['total']} total)</h2>
    {findings_html or "<div class='card' style='padding:32px;text-align:center;color:#6b7280'>✅ No vulnerabilities detected in this scan pass.</div>"}
  </section>
  <section>
    <h2>📚 References</h2>
    <ul style="padding-left:20px;font-size:.875rem;line-height:2.2">
      <li><a href="https://owasp.org/API-Security/">OWASP API Security Top 10 (2023)</a></li>
      <li><a href="https://owasp.org/www-project-top-ten/">OWASP Top 10 (2021)</a></li>
      <li><a href="https://www.first.org/cvss/v3.1/">CVSS v3.1 Specification</a></li>
      <li><a href="https://owasp.org/www-project-web-security-testing-guide/">OWASP Testing Guide</a></li>
    </ul>
  </section>
</div>
<footer>⚠️ Generated for authorized security testing only &nbsp;·&nbsp; API Security Scanner v2.0</footer>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
document.querySelectorAll('.fhdr').forEach(h=>{{
  h.addEventListener('click',()=>{{
    const b=h.nextElementSibling;
    b.classList.toggle('open');
    h.querySelector('.toggle').textContent=b.classList.contains('open')?'▲':'▼';
  }});
}});

// Chart.js - Severity Doughnut
const sevCounts = [
    {s["by_severity"].get("CRITICAL", 0)}, 
    {s["by_severity"].get("HIGH", 0)}, 
    {s["by_severity"].get("MEDIUM", 0)}, 
    {s["by_severity"].get("LOW", 0)}
];
new Chart(document.getElementById('severityChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{{
      data: sevCounts,
      backgroundColor: ['#dc2626', '#ea580c', '#d97706', '#2563eb'],
      borderWidth: 0
    }}]
  }},
  options: {{ 
    responsive: true, 
    maintainAspectRatio: false,
    plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12, font: {{ size: 10 }} }} }} }} 
  }}
}});

// Chart.js - Confidence
const confData = [
    {result.findings_count_by_status().get("Confirmed", 0)},
    {result.findings_count_by_status().get("Probable", 0)},
    {result.findings_count_by_status().get("Unconfirmed", 0)}
];
new Chart(document.getElementById('confidenceChart'), {{
  type: 'pie',
  data: {{
    labels: ['Confirmed', 'Probable', 'Unconfirmed'],
    datasets: [{{
      data: confData,
      backgroundColor: ['#16a34a', '#f59e0b', '#94a3b8'],
      borderWidth: 0
    }}]
  }},
  options: {{ 
    responsive: true, 
    maintainAspectRatio: false,
    plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12, font: {{ size: 10 }} }} }} }} 
  }}
}});

// Chart.js - OWASP
const owaspLabels = {list(s["by_owasp"].keys())};
const owaspData = {list(s["by_owasp"].values())};
new Chart(document.getElementById('owaspChart'), {{
  type: 'bar',
  data: {{
    labels: owaspLabels.map(l => l.split(':')[0]), // API1, API2...
    datasets: [{{
      label: 'Findings',
      data: owaspData,
      backgroundColor: '#3b82f6',
      borderRadius: 4
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1, font: {{ size: 9 }} }} }}, x: {{ ticks: {{ font: {{ size: 9 }} }} }} }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});
</script>
</body></html>"""

    def _summary_cards(self, s: dict) -> str:
        cards = ""
        for sev, col, bg in [
            ("CRITICAL","#dc2626","#fef2f2"),
            ("HIGH",    "#ea580c","#fff7ed"),
            ("MEDIUM",  "#d97706","#fffbeb"),
            ("LOW",     "#2563eb","#eff6ff"),
        ]:
            n = s["by_severity"].get(sev, 0)
            cards += f'<div class="card" style="border-top:3px solid {col}"><div class="lbl">{Severity(sev).emoji} {sev}</div><div class="val" style="color:{col}">{n}</div></div>'
        cards += f'<div class="card"><div class="lbl">Highest CVSS</div><div class="val">{s["highest_cvss"]}</div></div>'
        cards += f'<div class="card"><div class="lbl">Endpoints Found</div><div class="val">{s["endpoints_found"]}</div></div>'
        return cards

    def _findings_section(self, result: ScanResult) -> str:
        if not result.findings:
            return ""
        parts = []
        for f in result.sorted_findings():
            sev = f.severity
            col, bg = self._SEV_STYLE.get(sev, ("#6b7280", "#f9fafb"))
            conf_html = f'<span class="conf">✅ Confirmed</span>' if f.confirmed else f'<span class="unconf">⚠️ Unconfirmed</span>'

            def e(s): return escape(str(s))

            rec_items = "".join(
                f"<li>{e(line.strip().lstrip('0123456789. '))}</li>"
                for line in f.recommendation.split("\n") if line.strip()
            )
            payload_block = f"<p style='margin-top:10px'><strong>Payload:</strong></p><pre>{e(f.payload[:500])}</pre>" if f.payload and f.payload not in ("N/A","") else ""
            resp_block    = f"<p style='margin-top:10px'><strong>Server Response:</strong></p><pre>{e(f.truncate_response(500))}</pre>" if f.response_body else ""
            refs_block    = "".join(f'<div style="margin-top:4px"><a href="{e(r)}" style="font-size:.8rem">{e(r)}</a></div>' for r in f.references) if f.references else ""
            tags_block    = "<p style='margin-top:10px;font-size:.72rem;color:#94a3b8'>Tags: " + " ".join(f"<code>{e(t)}</code>" for t in f.tags) + "</p>" if f.tags else ""

            parts.append(f"""<div class="finding">
  <div class="fhdr" style="background:{bg}">
    <span class="badge" style="background:{col};color:#fff">{sev}</span>
    <span class="ftitle">{e(f.title)}</span>
    <span class="cvss-tag">CVSS {f.cvss_score}</span>
    {conf_html}
    <span class="toggle">▼</span>
  </div>
  <div class="fbody">
    <table>
      <tr><th colspan="2">Finding Details</th></tr>
      <tr><td>ID</td><td><code>{e(f.id)}</code></td></tr>
      <tr><td>Type</td><td>{e(f.vuln_type)}</td></tr>
      <tr><td>Endpoint</td><td><code>{e(f.endpoint)}</code></td></tr>
      <tr><td>Method</td><td><code>{f.method}</code></td></tr>
      <tr><td>Parameter</td><td>{e(f.parameter) if f.parameter else "—"}</td></tr>
      <tr><td>HTTP Status</td><td>{f.response_status}</td></tr>
      <tr><td>OWASP</td><td>{e(f.owasp_category)}</td></tr>
      <tr><td>CVSS Vector</td><td><code style="font-size:.72rem">{e(f.cvss_vector)}</code></td></tr>
      <tr><td>Response Time</td><td>{f.response_time_ms:.0f}ms</td></tr>
      <tr><td>Module</td><td>{e(f.module)}</td></tr>
    </table>
    <p class="desc" style="margin-top:14px"><strong>Description:</strong><br>{e(f.description)}</p>
    {payload_block}
    {resp_block}
    <div class="rec" style="margin-top:12px"><strong>✅ Recommendation:</strong><ul style="margin-top:6px;padding-left:16px">{rec_items}</ul></div>
    {refs_block}
    {tags_block}
  </div>
</div>""")
        return "\n".join(parts)


# ─── PDF ──────────────────────────────────────────────────────────────────────

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

class PDFReporter:
    def generate(self, result: ScanResult, path: str) -> str:
        if not FPDF:
            print("[!] fpdf2 not installed. Skipping PDF report.")
            return ""
        
        pdf = self._build(result)
        pdf.output(path)
        return path

    def _build(self, result: ScanResult) -> FPDF:
        s = result.summary
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # --- Cover Page ---
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 24)
        pdf.set_text_color(30, 58, 138)  # Deep Blue
        pdf.cell(0, 60, "API Security Audit Report", ln=True, align='C')
        
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 10, f"Target: {result.target}", ln=True, align='C')
        pdf.cell(0, 10, f"Date: {result.start_time[:19].replace('T', ' ')} UTC", ln=True, align='C')
        pdf.cell(0, 10, f"Scanner Version: v{result.scanner_version}", ln=True, align='C')
        
        # Big Score Section
        pdf.ln(30)
        pdf.set_fill_color(248, 250, 252)
        pdf.rect(60, 130, 90, 40, 'F')
        
        pdf.set_font("Helvetica", "B", 36)
        # Choose color by score
        score = s['security_score']
        if score >= 75: sc = (22, 163, 74) 
        elif score >= 50: sc = (217, 119, 6)
        else: sc = (220, 38, 38)
        
        pdf.set_text_color(*sc)
        pdf.set_xy(60, 140)
        pdf.cell(90, 15, f"{score}/100", align='C', ln=True)
        
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 10, f"RATING: {s['security_rating']}", align='C', ln=True)

        # --- Summary Page ---
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(30, 58, 138)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(0, 0, 0)
        
        # Table Headers
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(95, 10, "Metric", border=1, fill=True)
        pdf.cell(95, 10, "Value", border=1, fill=True, ln=True)
        
        # Table Rows
        pdf.set_font("Helvetica", "", 10)
        rows = [
            ["Total Findings", str(s['total'])],
            ["Confirmed Critical", str(s['by_severity'].get('CRITICAL', 0))],
            ["Highest CVSS", str(s['highest_cvss'])],
            ["Endpoints Discovered", str(s['endpoints_found'])],
            ["WAF Status", s.get('waf_detected') or "None Detected"],
        ]
        for r in rows:
            pdf.cell(95, 10, r[0], border=1)
            pdf.cell(95, 10, r[1], border=1, ln=True)

        # --- Findings ---
        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(30, 58, 138)
        pdf.cell(0, 10, "Security Findings Breakdown", ln=True)
        pdf.ln(5)

        by_sev = result.by_severity()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            f_list = by_sev.get(sev, [])
            if not f_list: continue
            
            # Severity Section Header
            pdf.set_font("Helvetica", "B", 12)
            sev_col = {"CRITICAL": (220, 38, 38), "HIGH": (234, 88, 12), "MEDIUM": (217, 119, 6), "LOW": (37, 99, 235), "INFO": (107, 114, 128)}
            pdf.set_text_color(*sev_col.get(sev, (0,0,0)))
            pdf.cell(0, 10, f"{sev} Severity - {len(f_list)} Item(s)", ln=True)
            pdf.ln(2)
            
            for f in f_list:
                # Page break check
                if pdf.get_y() > 240: pdf.add_page()
                
                # Finding Card
                pdf.set_fill_color(248, 250, 252)
                pdf.set_draw_color(200, 200, 200)
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(30, 58, 138)
                pdf.cell(0, 10, f" [{f.id}] {f.title}", border='LTR', ln=True, fill=True)
                
                # Meta
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(71, 85, 105)
                pdf.cell(0, 8, f" Endpoint: {f.method} {f.endpoint}", border='LR', ln=True)
                
                # Small Grid
                pdf.cell(47.5, 8, f" CVSS Score: {f.cvss_score}", border='LB')
                pdf.cell(47.5, 8, f" Status: {'Confirmed' if f.confirmed else 'Probable'}", border='B')
                pdf.cell(95, 8, f" Category: {f.owasp_category}", border='RB', ln=True)
                
                # Inner Details
                pdf.ln(3)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6, "Description:", ln=True)
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(0, 5, f.description)
                
                pdf.ln(2)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(22, 101, 52) # Greenish
                pdf.cell(0, 6, "Remediation Strategy:", ln=True)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(30, 41, 59)
                pdf.multi_cell(0, 5, f.recommendation)
                
                pdf.ln(6)
                pdf.set_draw_color(226, 232, 240)
                pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
                pdf.ln(4)
                
        return pdf
