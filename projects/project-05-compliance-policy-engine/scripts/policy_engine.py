"""
Compliance Policy Engine
========================
Orchestrates execution of all OPA Rego policies against
input state files and produces structured violation results.

CONTROL SYSTEM PARALLEL:
This engine functions as a Distributed Control System (DCS)
for compliance. A DCS runs many control loops concurrently,
each with its own setpoint and measurement. This engine runs
many compliance policies concurrently, each with its own
specification (Rego policy) and measurement (input state).

Both produce unified output for operators to act on.
"""

import json
import subprocess
import os
from datetime import datetime, timezone
from pathlib import Path


class CompliancePolicyEngine:
    """
    Runs OPA policies against input state files.
    Returns structured violations for downstream processing.
    """

    def __init__(self, project_root):
        """
        Args:
            project_root: Path to project-05-compliance-policy-engine
        """
        self.project_root = Path(project_root)
        self.policies_dir = self.project_root / "policies"
        self.inputs_dir = self.project_root / "sample-inputs"
        self.output_dir = self.project_root / "output"

        # Each entry maps a policy package to its input file
        # This is the policy-to-input routing table
        self.policy_routing = [
            {
                "domain": "iam",
                "package": "data.iam.access.deny",
                "policy_dir": "iam",
                "input_file": "iam-state.json",
                "soc2_mapping": "CC6.3",
                "iec62443_mapping": "FR2",
                "severity": "HIGH",
                "policy_name": "Least Privilege Enforcement"
            },
            {
                "domain": "iam",
                "package": "data.iam.mfa.deny",
                "policy_dir": "iam",
                "input_file": "iam-state.json",
                "soc2_mapping": "CC6.1",
                "iec62443_mapping": "FR1",
                "severity": "CRITICAL",
                "policy_name": "MFA Required"
            },
            {
                "domain": "iam",
                "package": "data.iam.mfa.deny_critical",
                "policy_dir": "iam",
                "input_file": "iam-state.json",
                "soc2_mapping": "CC6.1",
                "iec62443_mapping": "FR1",
                "severity": "CRITICAL",
                "policy_name": "MFA Required for Admin Users"
            },
            {
                "domain": "iam",
                "package": "data.iam.key_rotation.deny",
                "policy_dir": "iam",
                "input_file": "iam-state.json",
                "soc2_mapping": "CC6.7",
                "iec62443_mapping": "FR1",
                "severity": "HIGH",
                "policy_name": "Access Key Rotation"
            },
            {
                "domain": "iam",
                "package": "data.iam.key_rotation.deny_critical",
                "policy_dir": "iam",
                "input_file": "iam-state.json",
                "soc2_mapping": "CC6.7",
                "iec62443_mapping": "FR1",
                "severity": "CRITICAL",
                "policy_name": "Access Key Rotation Critical"
            },
            {
                "domain": "iam",
                "package": "data.iam.password_policy.deny",
                "policy_dir": "iam",
                "input_file": "iam-state.json",
                "soc2_mapping": "CC6.1",
                "iec62443_mapping": "FR1",
                "severity": "HIGH",
                "policy_name": "Password Policy Strength"
            },
            {
                "domain": "s3",
                "package": "data.s3.encryption.deny",
                "policy_dir": "s3",
                "input_file": "s3-state.json",
                "soc2_mapping": "CC6.7",
                "iec62443_mapping": "FR4",
                "severity": "HIGH",
                "policy_name": "S3 Encryption Required"
            },
            {
                "domain": "s3",
                "package": "data.s3.encryption.deny_critical",
                "policy_dir": "s3",
                "input_file": "s3-state.json",
                "soc2_mapping": "CC6.7",
                "iec62443_mapping": "FR4",
                "severity": "CRITICAL",
                "policy_name": "Sensitive S3 Encryption Critical"
            },
            {
                "domain": "s3",
                "package": "data.s3.public_access.deny",
                "policy_dir": "s3",
                "input_file": "s3-state.json",
                "soc2_mapping": "CC6.6",
                "iec62443_mapping": "FR5",
                "severity": "CRITICAL",
                "policy_name": "S3 Public Access Blocked"
            },
            {
                "domain": "network",
                "package": "data.network.exposure.deny",
                "policy_dir": "network",
                "input_file": "network-state.json",
                "soc2_mapping": "CC6.6",
                "iec62443_mapping": "FR5",
                "severity": "CRITICAL",
                "policy_name": "Network Sensitive Ports"
            }
        ]

    def run_policy(self, policy_config):
        """
        Execute a single OPA policy and return violations.

        Args:
            policy_config: Dict from policy_routing

        Returns:
            List of violation message strings (empty if compliant)
        """
        policy_path = self.policies_dir / policy_config["policy_dir"]
        input_path = self.inputs_dir / policy_config["input_file"]

        # Verify input file exists
        if not input_path.exists():
            print(f"  [SKIP] Input file not found: {input_path}")
            return []

        # Build OPA command
        cmd = [
            "opa", "eval",
            "--data", str(policy_path),
            "--input", str(input_path),
            "--format", "json",
            policy_config["package"]
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"  [ERROR] OPA failed: {result.stderr.strip()}")
                return []

            # Parse OPA JSON output
            opa_output = json.loads(result.stdout)

            # Navigate OPA's output structure
            # Format: result[0].expressions[0].value = list of messages
            violations = []
            for r in opa_output.get("result", []):
                for expr in r.get("expressions", []):
                    value = expr.get("value", [])
                    if isinstance(value, list):
                        violations.extend(value)

            return violations

        except subprocess.TimeoutExpired:
            print(f"  [ERROR] Policy timed out: {policy_config['package']}")
            return []
        except json.JSONDecodeError as e:
            print(f"  [ERROR] Could not parse OPA output: {e}")
            return []

    def run_all_policies(self):
        """
        Execute every policy and return structured results.

        Returns:
            Dict with metadata and findings list
        """
        scan_started = datetime.now(timezone.utc)

        print(f"\nCompliance Policy Engine")
        print(f"Scan started: {scan_started.isoformat()}")
        print(f"Policies to evaluate: {len(self.policy_routing)}")
        print()

        all_findings = []
        policies_executed = 0
        policies_with_violations = 0

        for policy_config in self.policy_routing:
            print(f"Evaluating: {policy_config['policy_name']}")
            print(f"  Package: {policy_config['package']}")

            violations = self.run_policy(policy_config)
            policies_executed += 1

            if violations:
                policies_with_violations += 1
                print(f"  [VIOLATIONS] {len(violations)} finding(s)")

                # Convert each violation message to a structured finding
                for violation_msg in violations:
                    finding = {
                        "policy_name": policy_config["policy_name"],
                        "policy_package": policy_config["package"],
                        "domain": policy_config["domain"],
                        "severity": policy_config["severity"],
                        "soc2_mapping": policy_config["soc2_mapping"],
                        "iec62443_mapping": policy_config["iec62443_mapping"],
                        "violation_message": violation_msg,
                        "detected_at": scan_started.isoformat()
                    }
                    all_findings.append(finding)
            else:
                print(f"  [PASS] No violations")
            print()

        scan_completed = datetime.now(timezone.utc)
        scan_duration = (scan_completed - scan_started).total_seconds()

        results = {
            "scan_metadata": {
                "scan_id": scan_started.strftime("%Y%m%d-%H%M%S"),
                "started_at": scan_started.isoformat(),
                "completed_at": scan_completed.isoformat(),
                "duration_seconds": round(scan_duration, 2),
                "engine_version": "1.0.0"
            },
            "scan_summary": {
                "policies_executed": policies_executed,
                "policies_with_violations": policies_with_violations,
                "policies_passing": policies_executed - policies_with_violations,
                "total_findings": len(all_findings),
                "compliance_score": round(
                    ((policies_executed - policies_with_violations) /
                     policies_executed * 100) if policies_executed else 0, 1
                )
            },
            "findings_by_severity": {
                "CRITICAL": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
                "HIGH": sum(1 for f in all_findings if f["severity"] == "HIGH"),
                "MEDIUM": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
                "LOW": sum(1 for f in all_findings if f["severity"] == "LOW")
            },
            "findings": all_findings
        }

        return results

    def save_results(self, results):
        """
        Save results to timestamped JSON in output directory.

        Args:
            results: Output from run_all_policies()

        Returns:
            Path to saved file
        """
        scan_id = results["scan_metadata"]["scan_id"]
        output_file = self.output_dir / f"policy-violations-{scan_id}.json"

        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        return output_file


def main():
    project_root = Path(__file__).parent.parent

    engine = CompliancePolicyEngine(project_root)
    results = engine.run_all_policies()
    output_file = engine.save_results(results)

    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Policies executed:        {results['scan_summary']['policies_executed']}")
    print(f"Policies passing:         {results['scan_summary']['policies_passing']}")
    print(f"Policies with violations: {results['scan_summary']['policies_with_violations']}")
    print(f"Total findings:           {results['scan_summary']['total_findings']}")
    print(f"Compliance score:         {results['scan_summary']['compliance_score']}%")
    print()
    print("Findings by severity:")
    for sev, count in results['findings_by_severity'].items():
        print(f"  {sev}: {count}")
    print()
    print(f"Results saved: {output_file}")


if __name__ == "__main__":
    main()
