"""
run_validator.py
================
Main entry point for the AWS Cloud Validator.

Run with:
    python3 run_validator.py

What it does:
    1. Collects IAM state from AWS
    2. Collects S3 state from AWS
    3. Validates IAM against security baselines
    4. Validates S3 against security baselines
    5. Generates JSON and Markdown reports
    6. Prints findings summary
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collectors.collect_iam_state import collect_and_save as collect_iam
from collectors.collect_s3_state  import collect_and_save as collect_s3
from validators.validate_iam      import validate_iam_state
from validators.validate_s3       import validate_s3_state
from validators.generate_report   import generate_report


def main():
    base_dir    = os.path.dirname(os.path.abspath(__file__))
    state_dir   = os.path.join(base_dir, "state")
    report_dir  = os.path.join(base_dir, "reports")
    evidence_dir = os.path.join(base_dir, "evidence")

    for d in [state_dir, report_dir, evidence_dir]:
        os.makedirs(d, exist_ok=True)

    print("\n" + "=" * 60)
    print("PAYsecure AWS CLOUD SECURITY VALIDATOR")
    print("=" * 60)

    # Phase 1: Collect state
    print("\n[PHASE 1] Collecting AWS State")
    collect_iam(state_dir)
    collect_s3(state_dir)

    # Phase 2: Validate
    print("\n[PHASE 2] Running Security Validations")
    iam_findings = validate_iam_state(state_dir)
    s3_findings  = validate_s3_state(state_dir)

    # Phase 3: Report
    print("\n[PHASE 3] Generating Reports")
    json_path, md_path = generate_report(
        iam_findings, s3_findings, report_dir
    )

    # Summary
    all_findings = iam_findings + s3_findings
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high     = [f for f in all_findings if f["severity"] == "HIGH"]

    print("\n" + "=" * 60)
    print("ASSESSMENT COMPLETE")
    print("=" * 60)
    print(f"Total Findings:   {len(all_findings)}")
    print(f"Critical:         {len(critical)}")
    print(f"High:             {len(high)}")
    print(f"JSON Report:      {json_path}")
    print(f"Markdown Report:  {md_path}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
