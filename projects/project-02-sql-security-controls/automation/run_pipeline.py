import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collect_evidence import collect_all_evidence
from generate_report import (
    calculate_compliance_score,
    generate_json_report,
    generate_markdown_report
)


def main():
    base_dir     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    evidence_dir = os.path.join(base_dir, "evidence")
    report_dir   = os.path.join(base_dir, "reports")

    os.makedirs(evidence_dir, exist_ok=True)
    os.makedirs(report_dir,   exist_ok=True)

    results   = collect_all_evidence(evidence_dir)
    score     = calculate_compliance_score(results)
    json_path = generate_json_report(results, score, report_dir)
    md_path   = generate_markdown_report(results, score, report_dir)

    print("\n" + "=" * 70)
    print("PIPELINE COMPLETE - SUMMARY")
    print("=" * 70)
    print(f"Compliance Score:   {score['overall_score']}%")
    print(f"Controls Passing:   {score['passing_controls']}/{score['scored_controls']}")
    print(f"Critical Findings:  {score['critical_findings']}")
    print(f"JSON Report:        {json_path}")
    print(f"Markdown Report:    {md_path}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
