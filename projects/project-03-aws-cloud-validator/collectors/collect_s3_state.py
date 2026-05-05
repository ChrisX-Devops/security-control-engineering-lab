"""
collect_s3_state.py
===================
Extracts AWS S3 bucket state using the AWS CLI.

What it collects:
    - All S3 buckets
    - Public access block settings
    - Versioning status
    - Encryption configuration
    - Logging configuration
"""

import json
import subprocess
import os
from datetime import datetime


def run_aws_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def collect_s3_buckets():
    """
    Collect all S3 buckets with their security configurations.

    Returns:
        list: bucket objects with security attributes
    """
    print("  Collecting S3 buckets...")

    response = run_aws_command([
        "aws", "s3api", "list-buckets",
        "--output", "json"
    ])

    if not response:
        print("  [WARN] Could not list S3 buckets")
        return []

    buckets = []

    for bucket in response.get("Buckets", []):
        name = bucket["Name"]
        print(f"    Processing bucket: {name}")

        bucket_data = {
            "name":                name,
            "created_date":        str(bucket.get("CreationDate", "")),
            "public_access_blocked": False,
            "versioning_enabled":  False,
            "encryption_enabled":  False,
            "logging_enabled":     False,
            "public_access_block": {}
        }

        # Check public access block
        pab_response = run_aws_command([
            "aws", "s3api",
            "get-bucket-policy-status",
            "--bucket", name,
            "--output", "json"
        ])

        pab_settings = run_aws_command([
            "aws", "s3api",
            "get-public-access-block",
            "--bucket", name,
            "--output", "json"
        ])

        if pab_settings:
            config = pab_settings.get(
                "PublicAccessBlockConfiguration", {}
            )
            bucket_data["public_access_block"] = config
            bucket_data["public_access_blocked"] = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False)
            ])

        # Check versioning
        versioning_response = run_aws_command([
            "aws", "s3api", "get-bucket-versioning",
            "--bucket", name,
            "--output", "json"
        ])
        if versioning_response:
            bucket_data["versioning_enabled"] = (
                versioning_response.get("Status") == "Enabled"
            )

        # Check encryption
        encryption_response = run_aws_command([
            "aws", "s3api",
            "get-bucket-encryption",
            "--bucket", name,
            "--output", "json"
        ])
        if encryption_response:
            bucket_data["encryption_enabled"] = True

        # Check logging
        logging_response = run_aws_command([
            "aws", "s3api",
            "get-bucket-logging",
            "--bucket", name,
            "--output", "json"
        ])
        if logging_response:
            bucket_data["logging_enabled"] = (
                "LoggingEnabled" in logging_response
            )

        buckets.append(bucket_data)

    return buckets


def collect_and_save(state_dir):
    print("\n[COLLECTING] AWS S3 State")
    print("=" * 50)

    today = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    state = {
        "collection_timestamp": timestamp,
        "collection_date":      today,
        "buckets":              collect_s3_buckets()
    }

    filename = f"s3-state-{today}.json"
    filepath = os.path.join(state_dir, filename)

    with open(filepath, "w") as f:
        json.dump(state, f, indent=2, default=str)

    print(f"\n[SAVED] S3 state: {filepath}")
    print(f"[INFO]  Buckets collected: {len(state['buckets'])}")

    return filepath


if __name__ == "__main__":
    state_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "state"
    )
    collect_and_save(state_dir)
