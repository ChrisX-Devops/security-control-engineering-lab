"""
collect_aws_findings.py
=======================
Pulls findings from the AWS Cloud Validator (Project 03)
and normalizes them into the unified finding format.

How it works:
    Reads the most recent JSON report produced by
    Project 03's run_validator.py and extracts findings.
    This avoids re-running AWS API calls unnecessarily.
"""

import json
import os
import glob
from datetime import datetime


def collect_aws_findings():
    """
    Read latest Project 03 report and normalize findings.

    Returns:
        list: normalized finding dicts
    """
    print("  Collecting AWS cloud findings...")

    project03_reports = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)
        ))),
        "project-03-aws-cloud-validator",
        "reports"
    )

    pattern = os.path.join(project03_reports, "cloud-report-*.json")
    report_files = sorted(glob.glob(pattern))

    if not report_files:
        print("  [WARN] No Project 03 reports found")
        print("  [INFO] Run project-03 validator first")
        return []

    latest_report = report_files[-1]
    print(f"  Reading: {os.path.basename(latest_report)}")

    with open(latest_report) as f:
        report = json.load(f)

    raw_findings = report.get("findings", [])
    normalized = []

    category_map = {
        "AWS-IAM": "identity",
        "AWS-S3":  "data_protection"
    }

    for f in raw_findings:
        prefix = "-".join(f["control_id"].split("-")[:2])
        category = category_map.get(prefix, "cloud_security")

        normalized.append({
            "finding_id":  f"AWS-{f['control_id']}-{f['resource'].replace('/', '-')}",
            "source":      "project-03-aws-validator",
            "control_id":  f["control_id"],
            "title":       f["title"],
            "severity":    f["severity"],
            "status":      f["status"],
            "resource":    f["resource"],
            "description": f["description"],
            "framework":   f["framework"],
            "category":    category
        })

    print(f"  Found {len(normalized)} AWS findings")
    return normalized
