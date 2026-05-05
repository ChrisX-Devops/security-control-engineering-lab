"""
run_dashboard.py
================
Main entry point for the Unified Compliance Dashboard.

Run with:
    python3 run_dashboard.py

What it does:
    1. Collects findings from Project 02 (SQL controls)
    2. Collects findings from Project 03 (AWS validator)
    3. Combines all findings into unified format
    4. Calculates overall compliance score
    5. Generates three reports:
       - unified-dashboard.json
       - unified-dashboard.md
       - remediation-plan.md
    6. Prints executive summary
"""

import os
import sys

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "collectors")
)

from collect_sql_findings  import collect_sql_findings
from collect_aws_findings  import collect_aws_findings
from scoring_engine        import calculate_score, prioritize_findings
from generate_unified_report import generate_unified_report


def main():
    base_dir   = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(base_dir, "reports")
    os.makedirs(report_dir, exist_ok=True)

    print("\n" + "=" * 60)
    print("PAYSECURE UNIFIED COMPLIANCE DASHBOARD")
    print("=" * 60)

    print("\n[PHASE 1] Collecting Findings From All Sources")
    print("-" * 60)

    sql_findings = collect_sql_findings()
    aws_findings = collect_aws_findings()

    all_findings = sql_findings + aws_findings

    print(f"\n  SQL findings:  {len(sql_findings)}")
    print(f"  AWS findings:  {len(aws_findings)}")
    print(f"  Total:         {len(all_findings)}")

    print("\n[PHASE 2] Calculating Compliance Score")
    print("-" * 60)

    score = calculate_score(all_findings)

    print(f"  Overall Score: {score['overall_score']}/100")
    print(f"  Grade:         {score['grade']}")
    print(f"  Status:        {score['status']}")

    print("\n[PHASE 3] Generating Reports")
    print("-" * 60)

    json_path, dashboard_path, remediation_path = \
        generate_unified_report(all_findings, score, report_dir)

    print(f"  Dashboard:     {dashboard_path}")
    print(f"  Remediation:   {remediation_path}")
    print(f"  JSON:          {json_path}")

    sorted_findings = prioritize_findings(all_findings)
    critical = [
        f for f in sorted_findings if f["severity"] == "CRITICAL"
    ]

    print("\n" + "=" * 60)
    print("EXECUTIVE SUMMARY")
    print("=" * 60)
    print(f"Compliance Score:  {score['overall_score']}/100"
          f"  (Grade {score['grade']} — {score['status']})")
    print(f"Total Findings:    {score['total_findings']}")
    print(f"Critical:          {score['counts'].get('CRITICAL', 0)}")
    print(f"High:              {score['counts'].get('HIGH', 0)}")
    print(f"Medium:            {score['counts'].get('MEDIUM', 0)}")
    print(f"Low:               {score['counts'].get('LOW', 0)}")

    if critical:
        print("\nCRITICAL FINDINGS REQUIRING IMMEDIATE ACTION:")
        for f in critical:
            print(f"  🚨 {f['title']} — {f['resource']}")

    print("\nSCORE BY CATEGORY:")
    for cat, data in score["category_scores"].items():
        label = cat.replace("_", " ").title()
        print(f"  {label}: {data['score']}/100"
              f" ({data['findings']} finding(s))")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
