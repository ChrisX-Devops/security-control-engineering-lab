"""
validate_iam.py
===============
Validates IAM state against security baselines.

Takes the JSON state file produced by collect_iam_state.py
and runs security checks against it.

Each check produces a finding dict:
    control_id:   unique identifier
    title:        human-readable name
    severity:     CRITICAL / HIGH / MEDIUM / LOW
    status:       PASS / FAIL
    resource:     what was checked
    description:  what the finding means
    framework:    SOC2 and ISO 27001 mappings
    remediation:  how to fix it
"""

import json
import os
from datetime import datetime


def load_state(state_dir):
    today = datetime.now().strftime("%Y-%m-%d")
    filepath = os.path.join(state_dir, f"iam-state-{today}.json")

    if not os.path.exists(filepath):
        print(f"[ERROR] State file not found: {filepath}")
        print("[INFO]  Run collectors/collect_iam_state.py first")
        return None

    with open(filepath) as f:
        return json.load(f)


def check_mfa_enabled(user):
    """Check if a user has MFA enabled."""
    if not user["mfa_enabled"]:
        return {
            "control_id":  "AWS-IAM-001",
            "title":       "MFA Not Enabled",
            "severity":    "CRITICAL",
            "status":      "FAIL",
            "resource":    f"iam/user/{user['username']}",
            "description": (
                f"User '{user['username']}' does not have MFA enabled. "
                f"If this account's password is compromised, an attacker "
                f"has unrestricted access."
            ),
            "framework":   "SOC2 CC6.1 | ISO A.9.4.2",
            "remediation": (
                "Go to IAM console → Users → Security credentials → "
                "Assign MFA device"
            )
        }
    return None


def check_access_key_age(user):
    """Check if any access keys are older than 90 days."""
    findings = []
    for key in user["access_keys"]:
        if key["status"] == "Active" and key["age_days"] > 90:
            findings.append({
                "control_id":  "AWS-IAM-002",
                "title":       "Access Key Older Than 90 Days",
                "severity":    "HIGH",
                "status":      "FAIL",
                "resource":    (
                    f"iam/user/{user['username']}/"
                    f"key/{key['access_key_id']}"
                ),
                "description": (
                    f"User '{user['username']}' has an active access key "
                    f"{key['age_days']} days old. Keys should be rotated "
                    f"every 90 days to limit exposure from leaked credentials."
                ),
                "framework":   "SOC2 CC6.1 | ISO A.9.2.6",
                "remediation": (
                    "Create a new access key, update applications, "
                    "then deactivate and delete the old key"
                )
            })
    return findings


def check_admin_access(user):
    """Check if a user has AdministratorAccess policy attached."""
    if "AdministratorAccess" in user["attached_policies"]:
        return {
            "control_id":  "AWS-IAM-003",
            "title":       "User Has Full Administrator Access",
            "severity":    "HIGH",
            "status":      "FAIL",
            "resource":    f"iam/user/{user['username']}",
            "description": (
                f"User '{user['username']}' has AdministratorAccess "
                f"policy attached. This grants unrestricted access to "
                f"all AWS services. Violates least privilege principle."
            ),
            "framework":   "SOC2 CC6.3 | ISO A.9.2.3",
            "remediation": (
                "Replace AdministratorAccess with a scoped policy "
                "that grants only the permissions this user needs"
            )
        }
    return None


def check_inline_policies(user):
    """Check if a user has inline policies (should use managed)."""
    if user["inline_policies"]:
        return {
            "control_id":  "AWS-IAM-004",
            "title":       "User Has Inline Policies",
            "severity":    "MEDIUM",
            "status":      "FAIL",
            "resource":    f"iam/user/{user['username']}",
            "description": (
                f"User '{user['username']}' has {len(user['inline_policies'])} "
                f"inline policy/policies. Inline policies are harder to "
                f"audit and manage than managed policies."
            ),
            "framework":   "SOC2 CC6.3 | ISO A.9.2.3",
            "remediation": (
                "Convert inline policies to customer-managed policies "
                "and attach them via groups"
            )
        }
    return None


def check_no_groups(user):
    """Check if a user is not in any group."""
    if not user["groups"]:
        return {
            "control_id":  "AWS-IAM-005",
            "title":       "User Not In Any Group",
            "severity":    "LOW",
            "status":      "FAIL",
            "resource":    f"iam/user/{user['username']}",
            "description": (
                f"User '{user['username']}' is not a member of any IAM group. "
                f"Best practice is to assign permissions via groups, "
                f"not directly to users."
            ),
            "framework":   "SOC2 CC6.3 | ISO A.9.2.1",
            "remediation": (
                "Create appropriate IAM groups, add user to group, "
                "move permissions to group level"
            )
        }
    return None


def validate_iam_state(state_dir):
    """
    Run all IAM validations against current state.

    Args:
        state_dir: path to state files

    Returns:
        list: all findings from IAM validation
    """
    print("\n[VALIDATING] IAM Security Controls")
    print("=" * 50)

    state = load_state(state_dir)
    if not state:
        return []

    users = state.get("users", [])
    print(f"  Validating {len(users)} IAM user(s)...\n")

    all_findings = []
    pass_count = 0

    for user in users:
        username = user["username"]
        user_findings = []

        mfa_finding = check_mfa_enabled(user)
        if mfa_finding:
            user_findings.append(mfa_finding)

        key_findings = check_access_key_age(user)
        user_findings.extend(key_findings)

        admin_finding = check_admin_access(user)
        if admin_finding:
            user_findings.append(admin_finding)

        inline_finding = check_inline_policies(user)
        if inline_finding:
            user_findings.append(inline_finding)

        group_finding = check_no_groups(user)
        if group_finding:
            user_findings.append(group_finding)

        if user_findings:
            print(f"  [!] {username}: {len(user_findings)} finding(s)")
            all_findings.extend(user_findings)
        else:
            print(f"  [OK] {username}: fully compliant")
            pass_count += 1

    print(f"\n  IAM Summary: {pass_count}/{len(users)} users fully compliant")
    print(f"  Total findings: {len(all_findings)}")

    return all_findings
