"""
Stakeholder Report Generator
============================
Converts policy engine scan results into stakeholder-ready
deliverables: executive summary and remediation runbook.

OUTPUT FORMATS:
- Executive report: Markdown for CTOs and founders
- Remediation runbook: Step-by-step fix instructions
- JSON dashboard feed: Machine-readable for monitoring tools
"""

import json
from pathlib import Path
from datetime import datetime, timezone


class ReportGenerator:
    """
    Generates stakeholder reports from scan results.
    """

    # Remediation guidance keyed by policy package
    REMEDIATION_GUIDE = {
        "data.iam.access.deny": {
            "action": "Replace AdministratorAccess with scoped policies",
            "steps": [
                "Identify what permissions the user actually needs",
                "Create or attach a scoped policy granting only those permissions",
                "Detach AdministratorAccess from the user",
                "Verify the user can still perform required tasks"
            ],
            "estimated_time": "30-60 minutes per user",
            "requires_change_window": False
        },
        "data.iam.mfa.deny": {
            "action": "Enable MFA device for affected user",
            "steps": [
                "Sign in to AWS IAM console as administrator",
                "Navigate to Users, select affected username",
                "Open Security Credentials tab",
                "Choose 'Assign MFA device'",
                "Use virtual MFA app (Authy, Google Authenticator) or hardware key",
                "Verify by signing out and signing back in with MFA"
            ],
            "estimated_time": "5-10 minutes per user",
            "requires_change_window": False
        },
        "data.iam.mfa.deny_critical": {
            "action": "URGENT: Enable MFA on admin account immediately",
            "steps": [
                "Stop all admin work until MFA is enabled",
                "Enable MFA via AWS console as documented in iam.mfa.deny",
                "Audit recent admin activity for unauthorized actions",
                "Document the gap and remediation time for audit trail"
            ],
            "estimated_time": "15 minutes plus activity audit",
            "requires_change_window": False
        },
        "data.iam.key_rotation.deny": {
            "action": "Rotate access key older than 90 days",
            "steps": [
                "Create new access key for the user",
                "Update applications and scripts to use new key",
                "Verify all systems are using the new key",
                "Disable the old access key (do not delete yet)",
                "Wait 24-48 hours for any missed integrations to surface",
                "Delete the old access key permanently"
            ],
            "estimated_time": "30-90 minutes depending on key usage scope",
            "requires_change_window": True
        },
        "data.iam.key_rotation.deny_critical": {
            "action": "URGENT: Rotate access key over 180 days old",
            "steps": [
                "Treat as potential credential exposure",
                "Audit CloudTrail for unusual activity from this key",
                "Rotate as documented in iam.key_rotation.deny",
                "Document compromise assessment in security log"
            ],
            "estimated_time": "1-2 hours including audit",
            "requires_change_window": True
        },
        "data.iam.password_policy.deny": {
            "action": "Strengthen account password policy",
            "steps": [
                "Sign in to AWS IAM console as administrator",
                "Navigate to Account settings",
                "Update password policy with: minimum 14 characters",
                "Enable: require symbols, numbers, uppercase, lowercase",
                "Save policy",
                "Communicate policy change to all users"
            ],
            "estimated_time": "15 minutes",
            "requires_change_window": False
        },
        "data.s3.encryption.deny": {
            "action": "Enable default encryption on S3 bucket",
            "steps": [
                "Open S3 console and select affected bucket",
                "Open Properties tab",
                "Find 'Default encryption' section",
                "Click Edit, choose SSE-S3 or SSE-KMS",
                "Save changes"
            ],
            "estimated_time": "5 minutes per bucket",
            "requires_change_window": False
        },
        "data.s3.encryption.deny_critical": {
            "action": "URGENT: Encrypt sensitive bucket immediately",
            "steps": [
                "Apply encryption as documented in s3.encryption.deny",
                "If bucket has existing unencrypted objects, plan re-encryption",
                "Document classification and remediation for compliance log"
            ],
            "estimated_time": "5 minutes for setting plus re-encryption time",
            "requires_change_window": False
        },
        "data.s3.public_access.deny": {
            "action": "Enable all public access block settings",
            "steps": [
                "Open S3 console, select affected bucket",
                "Open Permissions tab",
                "Find 'Block public access (bucket settings)'",
                "Click Edit",
                "Check all four block settings",
                "Save and confirm changes",
                "Test that legitimate access still works"
            ],
            "estimated_time": "10 minutes per bucket",
            "requires_change_window": False
        },
        "data.network.exposure.deny": {
            "action": "Restrict sensitive port from public internet",
            "steps": [
                "Identify the security group with the exposure",
                "Determine who legitimately needs access",
                "Replace 0.0.0.0/0 with specific CIDR ranges (VPN, office IPs)",
                "Or remove the rule if access is no longer needed",
                "Test legitimate access still works after restriction"
            ],
            "estimated_time": "15-30 minutes per security group",
            "requires_change_window": True
        }
    }

    def __init__(self, scan_file, output_dir):
        """
        Args:
            scan_file: Path to policy-violations JSON
            output_dir: Where to write reports
        """
        self.scan_file = Path(scan_file)
        self.output_dir = Path(output_dir)

        with open(self.scan_file) as f:
            self.scan_data = json.load(f)

    def generate_executive_report(self):
        """
        Generate Markdown executive summary.

        Returns:
            Path to saved report
        """
        scan_id = self.scan_data["scan_metadata"]["scan_id"]
        summary = self.scan_data["scan_summary"]
        severity_counts = self.scan_data["findings_by_severity"]

        score = summary["compliance_score"]
        if score >= 80:
            score_emoji = "GOOD"
        elif score >= 50:
            score_emoji = "NEEDS WORK"
        else:
            score_emoji = "URGENT"

        lines = []
        lines.append("# Compliance Assessment Report")
        lines.append("")
        lines.append(f"**Scan ID:** {scan_id}")
        lines.append(f"**Generated:** {self.scan_data['scan_metadata']['started_at']}")
        lines.append(f"**Compliance Score:** {score}/100 — {score_emoji}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(
            f"This assessment evaluated {summary['policies_executed']} security "
            f"control policies against your environment. "
            f"{summary['policies_passing']} controls passed without findings. "
            f"{summary['policies_with_violations']} controls produced violations "
            f"requiring action."
        )
        lines.append("")
        lines.append(
            f"**Total findings: {summary['total_findings']}** "
            f"({severity_counts['CRITICAL']} CRITICAL, "
            f"{severity_counts['HIGH']} HIGH, "
            f"{severity_counts['MEDIUM']} MEDIUM, "
            f"{severity_counts['LOW']} LOW)"
        )
        lines.append("")

        # Critical findings section
        critical = [
            f for f in self.scan_data["findings"]
            if f["severity"] == "CRITICAL"
        ]

        if critical:
            lines.append("## Critical Findings — Immediate Action Required")
            lines.append("")
            lines.append(
                f"The following {len(critical)} findings represent risks that "
                "should be addressed immediately. Each maps to specific SOC2 "
                "control criteria."
            )
            lines.append("")

            for i, finding in enumerate(critical, 1):
                lines.append(f"### {i}. {finding['policy_name']}")
                lines.append("")
                lines.append(f"**Finding:** {finding['violation_message']}")
                lines.append("")
                lines.append(f"- **Severity:** {finding['severity']}")
                lines.append(f"- **SOC2 Control:** {finding['soc2_mapping']}")
                lines.append(f"- **IEC 62443 Mapping:** {finding['iec62443_mapping']} (conceptual)")
                lines.append(f"- **Domain:** {finding['domain'].upper()}")
                lines.append("")

                # Add remediation if available
                remediation = self.REMEDIATION_GUIDE.get(finding["policy_package"])
                if remediation:
                    lines.append(f"**Recommended action:** {remediation['action']}")
                    lines.append(f"**Estimated time:** {remediation['estimated_time']}")
                    lines.append("")

        # High findings summary
        high = [
            f for f in self.scan_data["findings"]
            if f["severity"] == "HIGH"
        ]

        if high:
            lines.append("## High Severity Findings")
            lines.append("")
            lines.append(
                f"The following {len(high)} findings require attention "
                "within the next 7 days."
            )
            lines.append("")
            lines.append("| Finding | SOC2 | Policy |")
            lines.append("|---------|------|--------|")
            for finding in high:
                lines.append(
                    f"| {finding['violation_message'][:80]}... "
                    f"| {finding['soc2_mapping']} "
                    f"| {finding['policy_name']} |"
                )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("## Next Steps")
        lines.append("")
        lines.append("1. Review CRITICAL findings with engineering leadership")
        lines.append("2. Assign owners and timelines for each finding")
        lines.append("3. Run remediation runbook (see remediation-runbook-*.md)")
        lines.append("4. Re-scan after remediation to verify fixes")
        lines.append("")
        lines.append(
            "*This report was generated automatically by the Compliance Policy "
            "Engine. Findings map to SOC2 Trust Service Criteria and IEC 62443 "
            "Foundational Requirements (conceptual mapping only).*"
        )

        # Save
        report_file = self.output_dir / f"executive-report-{scan_id}.md"
        with open(report_file, "w") as f:
            f.write("\n".join(lines))

        return report_file

    def generate_remediation_runbook(self):
        """
        Generate detailed remediation runbook.

        Returns:
            Path to saved runbook
        """
        scan_id = self.scan_data["scan_metadata"]["scan_id"]

        lines = []
        lines.append("# Remediation Runbook")
        lines.append("")
        lines.append(f"**Scan ID:** {scan_id}")
        lines.append(f"**Total findings:** {self.scan_data['scan_summary']['total_findings']}")
        lines.append("")
        lines.append(
            "This runbook provides step-by-step remediation for every "
            "finding in the scan, ordered by severity."
        )
        lines.append("")
        lines.append("---")
        lines.append("")

        # Group findings by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

        for severity in severity_order:
            findings = [
                f for f in self.scan_data["findings"]
                if f["severity"] == severity
            ]

            if not findings:
                continue

            lines.append(f"## {severity} Severity Findings ({len(findings)})")
            lines.append("")

            for i, finding in enumerate(findings, 1):
                lines.append(f"### {severity}-{i}: {finding['policy_name']}")
                lines.append("")
                lines.append(f"**Violation:** {finding['violation_message']}")
                lines.append("")
                lines.append(f"**Framework mapping:**")
                lines.append(f"- SOC2: {finding['soc2_mapping']}")
                lines.append(f"- IEC 62443: {finding['iec62443_mapping']} (conceptual)")
                lines.append("")

                remediation = self.REMEDIATION_GUIDE.get(finding["policy_package"])

                if remediation:
                    lines.append(f"**Action:** {remediation['action']}")
                    lines.append("")
                    lines.append(f"**Estimated time:** {remediation['estimated_time']}")
                    lines.append("")
                    lines.append(
                        f"**Change window required:** "
                        f"{'Yes' if remediation['requires_change_window'] else 'No'}"
                    )
                    lines.append("")
                    lines.append("**Steps:**")
                    for step_num, step in enumerate(remediation["steps"], 1):
                        lines.append(f"{step_num}. {step}")
                    lines.append("")
                else:
                    lines.append(
                        "**Remediation guidance not available for this policy. "
                        "Contact security team for direction.**"
                    )
                    lines.append("")

                lines.append("---")
                lines.append("")

        runbook_file = self.output_dir / f"remediation-runbook-{scan_id}.md"
        with open(runbook_file, "w") as f:
            f.write("\n".join(lines))

        return runbook_file

    def generate_dashboard_json(self):
        """
        Generate machine-readable dashboard feed.

        Returns:
            Path to saved JSON
        """
        scan_id = self.scan_data["scan_metadata"]["scan_id"]

        dashboard_data = {
            "scan_id": scan_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "compliance_score": self.scan_data["scan_summary"]["compliance_score"],
            "total_findings": self.scan_data["scan_summary"]["total_findings"],
            "by_severity": self.scan_data["findings_by_severity"],
            "by_domain": self._group_by_domain(),
            "by_soc2_control": self._group_by_soc2()
        }

        dashboard_file = self.output_dir / f"dashboard-feed-{scan_id}.json"
        with open(dashboard_file, "w") as f:
            json.dump(dashboard_data, f, indent=2)

        return dashboard_file

    def _group_by_domain(self):
        """Count findings per domain."""
        counts = {}
        for finding in self.scan_data["findings"]:
            domain = finding["domain"]
            counts[domain] = counts.get(domain, 0) + 1
        return counts

    def _group_by_soc2(self):
        """Count findings per SOC2 control."""
        counts = {}
        for finding in self.scan_data["findings"]:
            soc2 = finding["soc2_mapping"]
            counts[soc2] = counts.get(soc2, 0) + 1
        return counts


def main():
    import sys

    project_root = Path(__file__).parent.parent
    output_dir = project_root / "output"

    # Use latest scan if no file specified
    if len(sys.argv) > 1:
        scan_file = Path(sys.argv[1])
    else:
        scan_files = sorted(output_dir.glob("policy-violations-*.json"))
        if not scan_files:
            print("No scan files found. Run policy_engine.py first.")
            return
        scan_file = scan_files[-1]

    print(f"Generating reports from: {scan_file.name}")
    print()

    generator = ReportGenerator(scan_file, output_dir)

    exec_report = generator.generate_executive_report()
    print(f"Executive report:    {exec_report}")

    runbook = generator.generate_remediation_runbook()
    print(f"Remediation runbook: {runbook}")

    dashboard = generator.generate_dashboard_json()
    print(f"Dashboard feed:      {dashboard}")


if __name__ == "__main__":
    main()
