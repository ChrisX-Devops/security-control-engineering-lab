"""
generate_unified_report.py
==========================
Generates the unified compliance dashboard report.

Produces three outputs:
    1. unified-dashboard.json  - machine readable, all data
    2. unified-dashboard.md    - executive report for clients
    3. remediation-plan.md     - prioritized action plan
"""

import json
import os
from datetime import datetime
from scoring_engine import prioritize_findings, SEVERITY_ORDER


def generate_unified_report(all_findings, score, report_dir):
    """
    Generate all three report formats.

    Args:
        all_findings: list of all normalized findings
        score:        scoring dict from scoring_engine
        report_dir:   path to save reports

    Returns:
        tuple: (json_path, dashboard_path, remediation_path)
    """
    today     = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sorted_findings = prioritize_findings(all_findings)

    json_path        = _generate_json(
        sorted_findings, score, report_dir, today, timestamp
    )
    dashboard_path   = _generate_dashboard_md(
        sorted_findings, score, report_dir, today, timestamp
    )
    remediation_path = _generate_remediation_plan(
        sorted_findings, score, report_dir, today, timestamp
    )

    return json_path, dashboard_path, remediation_path


def _generate_json(findings, score, report_dir, today, timestamp):
    report = {
        "metadata": {
            "generated_at":   timestamp,
            "report_date":    today,
            "system":         "PaySecure Unified Compliance Dashboard",
            "version":        "1.0"
        },
        "compliance_score": score,
        "findings":         findings
    }

    path = os.path.join(report_dir, f"unified-dashboard-{today}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return path


def _generate_dashboard_md(findings, score, report_dir,
                            today, timestamp):
    lines = []

    lines.append("# PaySecure Unified Compliance Dashboard")
    lines.append("")
    lines.append(f"**Report Date:** {today}")
    lines.append(f"**Generated:** {timestamp}")
    lines.append("")

    s = score["overall_score"]
    g = score["grade"]
    st = score["status"]

    if s >= 80:
        icon = "✅"
    elif s >= 60:
        icon = "⚠️"
    else:
        icon = "🚨"

    lines.append("## Overall Compliance Score")
    lines.append("")
    lines.append(
        f"# {icon} {s}/100 — Grade {g} — {st}"
    )
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Findings | {score['total_findings']} |")

    for sev in SEVERITY_ORDER:
        count = score["counts"].get(sev, 0)
        deduction = score["deductions"].get(sev, 0)
        lines.append(
            f"| {sev} Findings | {count} (-{deduction} pts) |"
        )
    lines.append("")

    lines.append("## Score by Category")
    lines.append("")
    lines.append("| Category | Score | Findings |")
    lines.append("|----------|-------|----------|")

    for cat, data in score["category_scores"].items():
        cat_label = cat.replace("_", " ").title()
        cat_score = data["score"]
        cat_findings = data["findings"]
        emoji = "✅" if cat_score >= 80 else "⚠️" if cat_score >= 60 \
            else "🚨"
        lines.append(
            f"| {emoji} {cat_label} | {cat_score}/100 | {cat_findings} |"
        )
    lines.append("")

    lines.append("## Findings by Source")
    lines.append("")

    sources = {}
    for f in findings:
        src = f["source"]
        sources.setdefault(src, []).append(f)

    for src, src_findings in sources.items():
        src_label = src.replace("-", " ").title()
        lines.append(f"### {src_label}")
        lines.append(f"**{len(src_findings)} finding(s)**")
        lines.append("")
        lines.append("| Severity | Title | Resource |")
        lines.append("|----------|-------|----------|")
        for f in prioritize_findings(src_findings):
            lines.append(
                f"| {f['severity']} | {f['title']} "
                f"| `{f['resource']}` |"
            )
        lines.append("")

    critical = [
        f for f in findings if f["severity"] == "CRITICAL"
    ]
    if critical:
        lines.append("## 🚨 Critical Findings — Act Immediately")
        lines.append("")
        for i, f in enumerate(critical, 1):
            lines.append(f"### {i}. {f['title']}")
            lines.append(f"- **Source:** {f['source']}")
            lines.append(f"- **Resource:** `{f['resource']}`")
            lines.append(f"- **Description:** {f['description']}")
            lines.append(f"- **Framework:** {f['framework']}")
            lines.append("")

    lines.append("---")
    lines.append(
        "*PaySecure Unified Compliance Dashboard — "
        "Confidential*"
    )

    path = os.path.join(
        report_dir, f"unified-dashboard-{today}.md"
    )
    with open(path, "w") as f:
        f.write("\n".join(lines))

    return path


def _generate_remediation_plan(findings, score, report_dir,
                                today, timestamp):
    lines = []

    lines.append("# Remediation Plan")
    lines.append("")
    lines.append(f"**Generated:** {timestamp}")
    lines.append(f"**Current Score:** {score['overall_score']}/100")
    lines.append("")
    lines.append(
        "Findings are ordered by priority. "
        "Fix CRITICAL items first."
    )
    lines.append("")

    sorted_findings = prioritize_findings(findings)

    for i, f in enumerate(sorted_findings, 1):
        sev = f["severity"]
        if sev == "CRITICAL":
            timeline = "Within 24 hours"
        elif sev == "HIGH":
            timeline = "Within 7 days"
        elif sev == "MEDIUM":
            timeline = "Within 30 days"
        else:
            timeline = "Within 90 days"

        deduction = {
            "CRITICAL": 20, "HIGH": 10,
            "MEDIUM": 5,    "LOW": 2
        }.get(sev, 0)

        lines.append(
            f"## {i}. [{sev}] {f['title']}"
        )
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Resource | `{f['resource']}` |")
        lines.append(f"| Source | {f['source']} |")
        lines.append(f"| Framework | {f['framework']} |")
        lines.append(f"| Timeline | {timeline} |")
        lines.append(
            f"| Score Impact | +{deduction} pts when fixed |"
        )
        lines.append("")
        lines.append(f"**Finding:** {f['description']}")
        lines.append("")

    potential = score["overall_score"] + sum(
        {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}.get(
            f["severity"], 0
        )
        for f in sorted_findings
    )

    lines.append("---")
    lines.append("## Score Projection")
    lines.append("")
    lines.append(
        f"Current score: **{score['overall_score']}/100**"
    )
    lines.append(
        f"Score after all remediations: "
        f"**{min(100, potential)}/100**"
    )
    lines.append("")
    lines.append(
        "*PaySecure Unified Compliance Dashboard — "
        "Confidential*"
    )

    path = os.path.join(
        report_dir, f"remediation-plan-{today}.md"
    )
    with open(path, "w") as f:
        f.write("\n".join(lines))

    return path
