"""Analysis Reports: aggregates findings into a scored JSON report + renders HTML."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.storage import models

SEVERITY_WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1, "Info": 0}
REPORTS_ROOT = Path(__file__).resolve().parent.parent.parent / "reports"

# source -> category label, for the per-category score breakdown on the report.
SOURCE_CATEGORY = {
    "android_checks": "Manifest & Config",
    "sast_engine": "Code Analysis",
    "malware_checks": "Malware Heuristics",
    "geolocation": "Network / Server",
    "firebase_checker": "Cloud / Firebase",
    "dynamic_frida": "Dynamic / Runtime",
}


def _category_deductions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-category (source) breakdown of finding counts and a 0-100 score,
    computed the same way as the overall security_score but scoped to each
    category — so the report can show *why* the overall score is what it is."""
    buckets: dict[str, dict[str, int]] = {}
    for f in findings:
        if f.get("triage_status") == "dismissed":
            continue
        category = SOURCE_CATEGORY.get(f["source"], f["source"])
        bucket = buckets.setdefault(category, {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0})
        bucket[f["severity"]] = bucket.get(f["severity"], 0) + 1

    breakdown = []
    for category, counts in buckets.items():
        deductions = counts["Critical"] * 15 + counts["High"] * 8 + counts["Medium"] * 3 + counts["Low"] * 1
        breakdown.append({
            "category": category,
            "score": max(0, min(100, 100 - deductions)),
            "total_findings": sum(counts.values()),
            "by_severity": counts,
        })
    breakdown.sort(key=lambda b: b["score"])
    return breakdown


def build_report(scan_id: str, parsed: dict[str, Any] | None = None) -> dict[str, Any]:
    """Aggregate a sample's stored findings into a scored report dict."""
    sample = models.get_sample(scan_id)
    findings = models.get_findings(scan_id)

    # Dismissed findings (triaged as false positives) don't count toward the
    # risk score or severity summary, but are still included in the findings
    # list so the UI can show them (visually de-emphasized).
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    score = 0
    for f in findings:
        if f.get("triage_status") == "dismissed":
            continue
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        score += SEVERITY_WEIGHT.get(sev, 0)

    # A 0-100 "security score" (100 = best) for an at-a-glance grade, separate
    # from the uncapped risk_score used for trend comparisons across scans.
    deductions = counts["Critical"] * 15 + counts["High"] * 8 + counts["Medium"] * 3 + counts["Low"] * 1
    security_score = max(0, min(100, 100 - deductions))
    category_breakdown = _category_deductions(findings)

    report = {
        "scan_id": scan_id,
        "sample": sample,
        "app": parsed,
        "findings": findings,
        "summary": {
            "total_findings": sum(counts.values()),
            "by_severity": counts,
            "risk_score": score,
            "security_score": security_score,
            "category_breakdown": category_breakdown,
            "dismissed_count": sum(1 for f in findings if f.get("triage_status") == "dismissed"),
        },
    }
    return report


def save_report(scan_id: str, report: dict[str, Any]) -> Path:
    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    json_path = REPORTS_ROOT / f"{scan_id}.json"
    html_path = REPORTS_ROOT / f"{scan_id}.html"

    json_path.write_text(json.dumps(report, indent=2, default=str))
    html_path.write_text(render_html(report))

    models.save_report(scan_id, json.dumps(report, default=str), str(html_path))
    return html_path


def render_html(report: dict[str, Any]) -> str:
    app = report.get("app") or {}
    summary = report["summary"]
    rows = "\n".join(
        f"""<tr class="sev-{f['severity'].lower()}">
              <td>{f['severity']}</td><td>{f['source']}</td>
              <td>{_escape(f['title'])}</td><td>{_escape(f.get('description', ''))}</td>
            </tr>"""
        for f in report["findings"]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Analysis Report — {_escape(app.get('package_name', report['scan_id']))}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; background: #0f1115; color: #e6e6e6; }}
  h1, h2 {{ color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid #2a2d34; text-align: left; vertical-align: top; }}
  th {{ background: #1a1d24; }}
  .meta {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin: 1rem 0; }}
  .card {{ background: #1a1d24; padding: 12px; border-radius: 8px; }}
  .sev-critical {{ border-left: 4px solid #ff4d4f; }}
  .sev-high {{ border-left: 4px solid #ff7a45; }}
  .sev-medium {{ border-left: 4px solid #ffc53d; }}
  .sev-low {{ border-left: 4px solid #73d13d; }}
  .sev-info {{ border-left: 4px solid #40a9ff; }}
  .score {{ font-size: 2rem; font-weight: bold; }}
</style>
</head>
<body>
  <h1>Android App Analysis Report</h1>
  <div class="meta">
    <div class="card"><strong>Package</strong><br>{_escape(app.get('package_name', 'N/A'))}</div>
    <div class="card"><strong>Version</strong><br>{_escape(str(app.get('version_name', 'N/A')))} ({app.get('version_code', 'N/A')})</div>
    <div class="card"><strong>SDK</strong><br>min {app.get('min_sdk', 'N/A')} / target {app.get('target_sdk', 'N/A')}</div>
    <div class="card"><strong>SHA-256</strong><br style="word-break:break-all">{_escape(app.get('sha256', 'N/A'))}</div>
    <div class="card"><strong>Risk score</strong><br><span class="score">{summary['risk_score']}</span></div>
    <div class="card"><strong>Findings</strong><br>
      Critical {summary['by_severity']['Critical']} ·
      High {summary['by_severity']['High']} ·
      Medium {summary['by_severity']['Medium']} ·
      Low {summary['by_severity']['Low']} ·
      Info {summary['by_severity']['Info']}
    </div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Source</th><th>Title</th><th>Description</th></tr></thead>
    <tbody>
      {rows or '<tr><td colspan="4">No findings.</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""


def build_trend(package_name: str) -> dict[str, Any]:
    """Risk score / finding-count trend across all scans of the same package,
    ordered chronologically (oldest first)."""
    samples = models.list_samples_by_package(package_name)
    points = []
    for sample in samples:
        report = build_report(sample["scan_id"])
        points.append({
            "scan_id": sample["scan_id"],
            "created_at": sample["created_at"],
            "risk_score": report["summary"]["risk_score"],
            "total_findings": report["summary"]["total_findings"],
            "by_severity": report["summary"]["by_severity"],
        })
    return {"package_name": package_name, "points": points}


def build_matrix(scan_ids: list[str]) -> dict[str, Any]:
    """Compare N scans (e.g. an entire release train) at once: every unique
    finding across all scans as a row, which scans it appears in as columns,
    plus a per-scan risk-score/finding-count summary row."""
    samples = [s for s in (models.get_sample(sid) for sid in scan_ids) if s]
    samples.sort(key=lambda s: s["created_at"])

    scan_reports = {s["scan_id"]: build_report(s["scan_id"]) for s in samples}

    finding_map: dict[tuple, dict[str, Any]] = {}
    for s in samples:
        for f in scan_reports[s["scan_id"]]["findings"]:
            if f.get("triage_status") == "dismissed":
                continue
            key = _finding_identity(f)
            entry = finding_map.setdefault(key, {
                "title": f["title"], "source": f["source"], "severity": f["severity"], "scan_ids": set(),
            })
            entry["scan_ids"].add(s["scan_id"])

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    scan_id_order = [s["scan_id"] for s in samples]
    rows = sorted(
        (
            {
                "title": data["title"],
                "source": data["source"],
                "severity": data["severity"],
                "present": [sid in data["scan_ids"] for sid in scan_id_order],
            }
            for data in finding_map.values()
        ),
        key=lambda r: (severity_order.get(r["severity"], 5), r["title"]),
    )

    scans_summary = [
        {
            "scan_id": s["scan_id"],
            "filename": s["filename"],
            "created_at": s["created_at"],
            "risk_score": scan_reports[s["scan_id"]]["summary"]["risk_score"],
            "total_findings": scan_reports[s["scan_id"]]["summary"]["total_findings"],
        }
        for s in samples
    ]

    return {"scans": scans_summary, "rows": rows}


def render_pdf_html(report: dict[str, Any]) -> str:
    """A simplified, table-based HTML variant for PDF rendering (xhtml2pdf's
    renderer doesn't support CSS grid/flexbox, so the summary uses a table)."""
    app = report.get("app") or {}
    summary = report["summary"]
    rows = "\n".join(
        f"""<tr>
              <td>{f['severity']}</td><td>{f['source']}</td>
              <td>{_escape(f['title'])}</td><td>{_escape(f.get('description', ''))}</td>
            </tr>"""
        for f in report["findings"]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Analysis Report — {_escape(app.get('package_name', report['scan_id']))}</title>
<style>
  body {{ font-family: Helvetica, sans-serif; color: #1d1d1f; font-size: 10pt; }}
  h1 {{ font-size: 18pt; }}
  h2 {{ font-size: 13pt; margin-top: 16pt; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8pt; }}
  th, td {{ padding: 4pt 6pt; border-bottom: 1px solid #e0e0e0; text-align: left; vertical-align: top; font-size: 8pt; }}
  th {{ background: #f5f5f7; }}
  .meta-table td {{ font-size: 9pt; padding: 4pt 8pt; border: 1px solid #e0e0e0; }}
  .score {{ font-size: 16pt; font-weight: bold; }}
</style>
</head>
<body>
  <h1>Android App Analysis Report</h1>
  <table class="meta-table">
    <tr><td><strong>Package</strong></td><td>{_escape(app.get('package_name', 'N/A'))}</td></tr>
    <tr><td><strong>Version</strong></td><td>{_escape(str(app.get('version_name', 'N/A')))} ({app.get('version_code', 'N/A')})</td></tr>
    <tr><td><strong>SDK</strong></td><td>min {app.get('min_sdk', 'N/A')} / target {app.get('target_sdk', 'N/A')}</td></tr>
    <tr><td><strong>SHA-256</strong></td><td>{_escape(app.get('sha256', 'N/A'))}</td></tr>
    <tr><td><strong>Risk score</strong></td><td class="score">{summary['risk_score']}</td></tr>
    <tr><td><strong>Findings</strong></td><td>
      Critical {summary['by_severity']['Critical']} ·
      High {summary['by_severity']['High']} ·
      Medium {summary['by_severity']['Medium']} ·
      Low {summary['by_severity']['Low']} ·
      Info {summary['by_severity']['Info']}
    </td></tr>
  </table>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Source</th><th>Title</th><th>Description</th></tr></thead>
    <tbody>
      {rows or '<tr><td colspan="4">No findings.</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""


def save_report_pdf(scan_id: str, report: dict[str, Any]) -> Path:
    """Render the report to PDF and save it alongside the JSON/HTML reports."""
    from xhtml2pdf import pisa

    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    pdf_path = REPORTS_ROOT / f"{scan_id}.pdf"
    html = render_pdf_html(report)

    with open(pdf_path, "wb") as f:
        result = pisa.CreatePDF(html, dest=f)
    if result.err:
        raise RuntimeError(f"PDF generation failed for scan {scan_id} ({result.err} error(s))")
    return pdf_path


def _finding_identity(f: dict[str, Any]) -> tuple:
    """A stable identity for matching the same finding across two scans.

    Title alone isn't unique — many findings (entropy secrets, repeated
    pattern matches) share an identical title and differ only by the
    specific matched snippet or rule id in metadata, so those must be part
    of the identity too.
    """
    metadata = f.get("metadata") or {}
    return (f["source"], f["title"], metadata.get("rule_id"), metadata.get("snippet"))


def diff_reports(scan_id_a: str, scan_id_b: str) -> dict[str, Any]:
    """Compare findings between two scans (e.g. two versions of the same package).

    Findings are matched by source/title/rule/snippet since there's no stable
    finding ID across scans; a finding is "new" if it appears in B but not A,
    "resolved" if it appears in A but not B.
    """
    findings_a = models.get_findings(scan_id_a)
    findings_b = models.get_findings(scan_id_b)

    keys_a = {_finding_identity(f) for f in findings_a}
    keys_b = {_finding_identity(f) for f in findings_b}

    new_findings = [f for f in findings_b if _finding_identity(f) not in keys_a]
    resolved_findings = [f for f in findings_a if _finding_identity(f) not in keys_b]
    unchanged_count = len(keys_a & keys_b)

    return {
        "scan_a": models.get_sample(scan_id_a),
        "scan_b": models.get_sample(scan_id_b),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_count": unchanged_count,
    }


def _escape(s: Any) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
