"""
Standing Alarm Detector
=======================
Identifies chronic compliance findings that persist across
multiple scans. Inspired by ISA 18.2 alarm management.

PRINCIPLE:
A new finding is a discovery requiring investigation.
A finding present in 3+ consecutive scans is a standing
alarm requiring escalation.

Standing alarms indicate:
- Process failure (the team is not addressing findings)
- Capability gap (the team cannot fix this type of issue)
- Risk acceptance without documentation
- Forgotten or deprioritized work

Identifying standing alarms is more valuable than identifying
new ones because they reveal systemic issues.
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict


class StandingAlarmDetector:
    """
    Analyzes scan history to identify chronic findings.
    """

    def __init__(self, output_dir):
        """
        Args:
            output_dir: Path to project output directory
        """
        self.output_dir = Path(output_dir)
        self.standing_threshold = 3  # Minimum scans to be "standing"

    def load_scan_history(self):
        """
        Load all policy violation JSON files from output directory.

        Returns:
            List of scan results sorted oldest to newest
        """
        scan_files = sorted(
            self.output_dir.glob("policy-violations-*.json")
        )

        scans = []
        for scan_file in scan_files:
            with open(scan_file) as f:
                scan_data = json.load(f)
                scans.append(scan_data)

        return scans

    def fingerprint_finding(self, finding):
        """
        Create a unique identifier for a finding.

        Two findings with the same fingerprint are the
        same underlying issue across different scans.

        Args:
            finding: A finding dict from scan results

        Returns:
            String fingerprint
        """
        return f"{finding['policy_package']}|{finding['violation_message']}"

    def detect_standing_alarms(self):
        """
        Find findings present in N or more consecutive scans.

        Returns:
            Dict with standing alarm analysis
        """
        scans = self.load_scan_history()

        if len(scans) < self.standing_threshold:
            return {
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "scans_analyzed": len(scans),
                "standing_threshold": self.standing_threshold,
                "status": "INSUFFICIENT_HISTORY",
                "message": (
                    f"Need at least {self.standing_threshold} scans for "
                    f"standing alarm detection. Currently have {len(scans)}."
                ),
                "standing_alarms": []
            }

        # Track which scans contain each finding
        finding_appearances = defaultdict(list)

        for scan in scans:
            scan_id = scan["scan_metadata"]["scan_id"]
            scan_time = scan["scan_metadata"]["started_at"]

            for finding in scan.get("findings", []):
                fingerprint = self.fingerprint_finding(finding)
                finding_appearances[fingerprint].append({
                    "scan_id": scan_id,
                    "scan_time": scan_time,
                    "finding": finding
                })

        # Identify standing alarms (appears in last N consecutive scans)
        recent_scans = scans[-self.standing_threshold:]
        recent_scan_ids = {
            s["scan_metadata"]["scan_id"] for s in recent_scans
        }

        standing_alarms = []

        for fingerprint, appearances in finding_appearances.items():
            appearance_scan_ids = {a["scan_id"] for a in appearances}

            # Standing alarm: present in all recent scans
            if recent_scan_ids.issubset(appearance_scan_ids):
                first_seen = appearances[0]
                latest = appearances[-1]

                first_time = datetime.fromisoformat(
                    first_seen["scan_time"].replace("Z", "+00:00")
                )
                latest_time = datetime.fromisoformat(
                    latest["scan_time"].replace("Z", "+00:00")
                )
                duration_days = (latest_time - first_time).days

                standing_alarms.append({
                    "fingerprint": fingerprint,
                    "policy_name": first_seen["finding"]["policy_name"],
                    "severity": first_seen["finding"]["severity"],
                    "soc2_mapping": first_seen["finding"]["soc2_mapping"],
                    "violation_message": first_seen["finding"]["violation_message"],
                    "first_seen": first_seen["scan_time"],
                    "latest_seen": latest["scan_time"],
                    "consecutive_scans": len(appearances),
                    "days_outstanding": duration_days,
                    "escalation_status": self.classify_escalation(
                        first_seen["finding"]["severity"],
                        duration_days
                    )
                })

        # Sort by escalation priority (CRITICAL standing first)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        standing_alarms.sort(
            key=lambda x: (
                severity_order.get(x["severity"], 99),
                -x["days_outstanding"]
            )
        )

        return {
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "scans_analyzed": len(scans),
            "standing_threshold": self.standing_threshold,
            "status": "ANALYSIS_COMPLETE",
            "total_standing_alarms": len(standing_alarms),
            "standing_by_severity": {
                "CRITICAL": sum(1 for a in standing_alarms if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in standing_alarms if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in standing_alarms if a["severity"] == "MEDIUM"),
                "LOW": sum(1 for a in standing_alarms if a["severity"] == "LOW")
            },
            "standing_alarms": standing_alarms
        }

    def classify_escalation(self, severity, days_outstanding):
        """
        Determine escalation status based on severity and duration.

        Args:
            severity: CRITICAL/HIGH/MEDIUM/LOW
            days_outstanding: Days since first detection

        Returns:
            Escalation classification string
        """
        if severity == "CRITICAL":
            if days_outstanding >= 7:
                return "EXECUTIVE_ESCALATION"
            elif days_outstanding >= 1:
                return "MANAGEMENT_ESCALATION"
            else:
                return "TEAM_LEAD_AWARE"

        if severity == "HIGH":
            if days_outstanding >= 30:
                return "MANAGEMENT_ESCALATION"
            elif days_outstanding >= 7:
                return "TEAM_LEAD_AWARE"
            else:
                return "STANDARD_TRACKING"

        if severity == "MEDIUM":
            if days_outstanding >= 90:
                return "TEAM_LEAD_AWARE"
            else:
                return "STANDARD_TRACKING"

        return "STANDARD_TRACKING"

    def save_analysis(self, analysis):
        """
        Save standing alarm analysis to timestamped file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        output_file = self.output_dir / f"standing-alarms-{timestamp}.json"

        with open(output_file, "w") as f:
            json.dump(analysis, f, indent=2)

        return output_file


def main():
    project_root = Path(__file__).parent.parent
    output_dir = project_root / "output"

    print("Standing Alarm Detector")
    print("=" * 60)

    detector = StandingAlarmDetector(output_dir)
    analysis = detector.detect_standing_alarms()

    if analysis["status"] == "INSUFFICIENT_HISTORY":
        print(f"\n{analysis['message']}")
        print(f"\nRun the policy engine more times to build history.")
        return

    output_file = detector.save_analysis(analysis)

    print(f"\nScans analyzed: {analysis['scans_analyzed']}")
    print(f"Standing threshold: {analysis['standing_threshold']} consecutive scans")
    print(f"Total standing alarms: {analysis['total_standing_alarms']}")
    print(f"\nStanding alarms by severity:")
    for sev, count in analysis['standing_by_severity'].items():
        print(f"  {sev}: {count}")

    if analysis["standing_alarms"]:
        print(f"\nTop 5 standing alarms requiring escalation:")
        for i, alarm in enumerate(analysis["standing_alarms"][:5], 1):
            print(
                f"  {i}. [{alarm['severity']}] "
                f"{alarm['days_outstanding']} days outstanding "
                f"({alarm['escalation_status']})"
            )
            print(f"     {alarm['violation_message']}")

    print(f"\nAnalysis saved: {output_file}")


if __name__ == "__main__":
    main()
