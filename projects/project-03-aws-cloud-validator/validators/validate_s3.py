"""
validate_s3.py
==============
Validates S3 bucket state against security baselines.
"""

import json
import os
from datetime import datetime


def load_state(state_dir):
    today = datetime.now().strftime("%Y-%m-%d")
    filepath = os.path.join(state_dir, f"s3-state-{today}.json")

    if not os.path.exists(filepath):
        print(f"[WARN] S3 state file not found: {filepath}")
        return None

    with open(filepath) as f:
        return json.load(f)


def check_public_access(bucket):
    if not bucket["public_access_blocked"]:
        return {
            "control_id":  "AWS-S3-001",
            "title":       "S3 Bucket Public Access Not Blocked",
            "severity":    "CRITICAL",
            "status":      "FAIL",
            "resource":    f"s3/{bucket['name']}",
            "description": (
                f"Bucket '{bucket['name']}' does not have all public "
                f"access block settings enabled. This bucket may be "
                f"accessible to the internet."
            ),
            "framework":   "SOC2 CC6.1, CC6.6 | ISO A.13.1.3",
            "remediation": (
                "Enable all 4 public access block settings: "
                "BlockPublicAcls, IgnorePublicAcls, "
                "BlockPublicPolicy, RestrictPublicBuckets"
            )
        }
    return None


def check_versioning(bucket):
    if not bucket["versioning_enabled"]:
        return {
            "control_id":  "AWS-S3-002",
            "title":       "S3 Bucket Versioning Not Enabled",
            "severity":    "MEDIUM",
            "status":      "FAIL",
            "resource":    f"s3/{bucket['name']}",
            "description": (
                f"Bucket '{bucket['name']}' does not have versioning "
                f"enabled. Without versioning, deleted or overwritten "
                f"objects cannot be recovered."
            ),
            "framework":   "SOC2 CC9.1 | ISO A.12.3.1",
            "remediation": (
                "Enable versioning in S3 bucket properties. "
                "Consider also enabling MFA delete for critical buckets."
            )
        }
    return None


def check_encryption(bucket):
    if not bucket["encryption_enabled"]:
        return {
            "control_id":  "AWS-S3-003",
            "title":       "S3 Bucket Encryption Not Enabled",
            "severity":    "HIGH",
            "status":      "FAIL",
            "resource":    f"s3/{bucket['name']}",
            "description": (
                f"Bucket '{bucket['name']}' does not have server-side "
                f"encryption enabled. Data at rest is not encrypted."
            ),
            "framework":   "SOC2 CC6.1 | ISO A.10.1.1",
            "remediation": (
                "Enable default encryption on the bucket using "
                "SSE-S3 or SSE-KMS"
            )
        }
    return None


def check_logging(bucket):
    if not bucket["logging_enabled"]:
        return {
            "control_id":  "AWS-S3-004",
            "title":       "S3 Bucket Access Logging Not Enabled",
            "severity":    "MEDIUM",
            "status":      "FAIL",
            "resource":    f"s3/{bucket['name']}",
            "description": (
                f"Bucket '{bucket['name']}' does not have access "
                f"logging enabled. Without logging, you cannot audit "
                f"who accessed or modified bucket contents."
            ),
            "framework":   "SOC2 CC7.2 | ISO A.12.4.1",
            "remediation": (
                "Enable server access logging in S3 bucket properties. "
                "Choose a target bucket to store the log files."
            )
        }
    return None


def validate_s3_state(state_dir):
    """
    Run all S3 validations against current state.

    Args:
        state_dir: path to state files

    Returns:
        list: all findings from S3 validation
    """
    print("\n[VALIDATING] S3 Security Controls")
    print("=" * 50)

    state = load_state(state_dir)
    if not state:
        print("  [SKIP] No S3 state file found")
        print("  [INFO] If you have no S3 buckets this is normal")
        return []

    buckets = state.get("buckets", [])

    if not buckets:
        print("  [INFO] No S3 buckets found in account")
        return []

    print(f"  Validating {len(buckets)} S3 bucket(s)...\n")

    all_findings = []
    pass_count = 0

    for bucket in buckets:
        name = bucket["name"]
        bucket_findings = []

        public_finding = check_public_access(bucket)
        if public_finding:
            bucket_findings.append(public_finding)

        versioning_finding = check_versioning(bucket)
        if versioning_finding:
            bucket_findings.append(versioning_finding)

        encryption_finding = check_encryption(bucket)
        if encryption_finding:
            bucket_findings.append(encryption_finding)

        logging_finding = check_logging(bucket)
        if logging_finding:
            bucket_findings.append(logging_finding)

        if bucket_findings:
            print(f"  [!] {name}: {len(bucket_findings)} finding(s)")
            all_findings.extend(bucket_findings)
        else:
            print(f"  [OK] {name}: fully compliant")
            pass_count += 1

    print(f"\n  S3 Summary: {pass_count}/{len(buckets)} buckets fully compliant")
    print(f"  Total findings: {len(all_findings)}")

    return all_findings
