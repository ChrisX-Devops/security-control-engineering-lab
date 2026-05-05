"""
collect_iam_state.py
====================
Extracts AWS IAM state using the AWS CLI.

What it collects:
    - All IAM users
    - Their attached policies
    - Their MFA status
    - Their access keys and age
    - Account password policy

Why JSON output:
    JSON is machine-readable. The validator scripts
    read this JSON and check it against security rules.
    This separates data collection from validation logic.
"""

import json
import subprocess
import sys
import os
from datetime import datetime, timezone


def run_aws_command(command):
    """
    Run an AWS CLI command and return parsed JSON output.

    Args:
        command: list of strings forming the AWS CLI command

    Returns:
        dict or list: parsed JSON response
        None: if command fails
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"  [WARN] Command failed: {' '.join(command)}")
            print(f"  [WARN] Error: {result.stderr.strip()}")
            return None

        return json.loads(result.stdout)

    except subprocess.TimeoutExpired:
        print(f"  [WARN] Command timed out: {' '.join(command)}")
        return None

    except json.JSONDecodeError:
        print(f"  [WARN] Could not parse JSON from: {' '.join(command)}")
        return None


def collect_iam_users():
    """
    Collect all IAM users with their security attributes.

    Returns:
        list: user objects with security-relevant fields
    """
    print("  Collecting IAM users...")

    response = run_aws_command([
        "aws", "iam", "list-users",
        "--output", "json"
    ])

    if not response:
        return []

    users = []

    for user in response.get("Users", []):
        username = user["UserName"]
        print(f"    Processing user: {username}")

        user_data = {
            "username":          username,
            "user_id":           user.get("UserId"),
            "arn":               user.get("Arn"),
            "created_date":      str(user.get("CreateDate", "")),
            "password_last_used": str(user.get("PasswordLastUsed", "Never")),
            "mfa_enabled":       False,
            "mfa_devices":       [],
            "access_keys":       [],
            "attached_policies": [],
            "inline_policies":   [],
            "groups":            []
        }

        # Check MFA devices
        mfa_response = run_aws_command([
            "aws", "iam", "list-mfa-devices",
            "--user-name", username,
            "--output", "json"
        ])
        if mfa_response:
            devices = mfa_response.get("MFADevices", [])
            user_data["mfa_devices"] = devices
            user_data["mfa_enabled"] = len(devices) > 0

        # Check access keys
        keys_response = run_aws_command([
            "aws", "iam", "list-access-keys",
            "--user-name", username,
            "--output", "json"
        ])
        if keys_response:
            for key in keys_response.get("AccessKeyMetadata", []):
                created = key.get("CreateDate", "")
                age_days = 0

                if created:
                    try:
                        created_dt = datetime.fromisoformat(
                            str(created).replace("Z", "+00:00")
                        )
                        age_days = (
                            datetime.now(timezone.utc) - created_dt
                        ).days
                    except Exception:
                        age_days = 0

                user_data["access_keys"].append({
                    "access_key_id": key.get("AccessKeyId"),
                    "status":        key.get("Status"),
                    "created_date":  str(created),
                    "age_days":      age_days
                })

        # Check attached policies
        policies_response = run_aws_command([
            "aws", "iam", "list-attached-user-policies",
            "--user-name", username,
            "--output", "json"
        ])
        if policies_response:
            user_data["attached_policies"] = [
                p["PolicyName"]
                for p in policies_response.get("AttachedPolicies", [])
            ]

        # Check inline policies
        inline_response = run_aws_command([
            "aws", "iam", "list-user-policies",
            "--user-name", username,
            "--output", "json"
        ])
        if inline_response:
            user_data["inline_policies"] = \
                inline_response.get("PolicyNames", [])

        # Check groups
        groups_response = run_aws_command([
            "aws", "iam", "list-groups-for-user",
            "--user-name", username,
            "--output", "json"
        ])
        if groups_response:
            user_data["groups"] = [
                g["GroupName"]
                for g in groups_response.get("Groups", [])
            ]

        users.append(user_data)

    return users


def collect_account_summary():
    """
    Collect AWS account-level IAM summary.

    Returns:
        dict: account summary data
    """
    print("  Collecting account summary...")

    response = run_aws_command([
        "aws", "iam", "get-account-summary",
        "--output", "json"
    ])

    if not response:
        return {}

    return response.get("SummaryMap", {})


def collect_password_policy():
    """
    Collect the account password policy.

    Returns:
        dict: password policy settings or empty dict if none set
    """
    print("  Collecting password policy...")

    response = run_aws_command([
        "aws", "iam", "get-account-password-policy",
        "--output", "json"
    ])

    if not response:
        return {"policy_exists": False}

    policy = response.get("PasswordPolicy", {})
    policy["policy_exists"] = True
    return policy


def collect_and_save(state_dir):
    """
    Run all collectors and save state to JSON files.

    Args:
        state_dir: path to save state files

    Returns:
        dict: paths to all saved state files
    """
    print("\n[COLLECTING] AWS IAM State")
    print("=" * 50)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    today = datetime.now().strftime("%Y-%m-%d")

    state = {
        "collection_timestamp": timestamp,
        "collection_date":      today,
        "users":                collect_iam_users(),
        "account_summary":      collect_account_summary(),
        "password_policy":      collect_password_policy()
    }

    filename = f"iam-state-{today}.json"
    filepath = os.path.join(state_dir, filename)

    with open(filepath, "w") as f:
        json.dump(state, f, indent=2, default=str)

    print(f"\n[SAVED] IAM state: {filepath}")
    print(f"[INFO]  Users collected: {len(state['users'])}")

    return filepath


if __name__ == "__main__":
    state_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "state"
    )
    collect_and_save(state_dir)
