import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_connect import get_connection, run_query
from controls import CONTROLS


def format_results_as_text(control, columns, rows):
    lines = []
    lines.append("=" * 70)
    lines.append(f"CONTROL: {control['id']} - {control['name']}")
    lines.append(f"Severity:    {control['severity']}")
    lines.append(f"Framework:   {control['framework']}")
    lines.append(f"Description: {control['description']}")
    lines.append(f"Run Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)

    if not rows:
        lines.append("RESULT: NO VIOLATIONS FOUND - CONTROL PASSING")
    else:
        lines.append(f"RESULT: {len(rows)} FINDING(S) DETECTED")
        lines.append("")
        lines.append("  ".join(str(col).upper() for col in columns))
        lines.append("-" * 70)
        for row in rows:
            lines.append("  ".join(str(val) for val in row))

    lines.append("")
    return "\n".join(lines)


def save_evidence_file(control, content, evidence_dir):
    today = datetime.now().strftime("%Y-%m-%d")
    control_id = control["id"].lower().replace("-", "")
    filename = f"{control_id}-evidence-{today}.txt"
    filepath = os.path.join(evidence_dir, filename)

    with open(filepath, "w") as f:
        f.write(content)

    return filepath


def collect_all_evidence(evidence_dir):
    print("\n" + "=" * 70)
    print("AUTOMATED EVIDENCE COLLECTION PIPELINE")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70 + "\n")

    connection = get_connection()
    print("[OK] Connected to database: security_logs\n")

    results = []

    for control in CONTROLS:
        print(f"Running {control['id']}: {control['name']}...")

        try:
            columns, rows = run_query(connection, control["sql"])
            content = format_results_as_text(control, columns, rows)
            filepath = save_evidence_file(control, content, evidence_dir)

            status = "PASS" if not rows else "FINDINGS"
            finding_count = len(rows)

            results.append({
                "control_id":    control["id"],
                "name":          control["name"],
                "severity":      control["severity"],
                "framework":     control["framework"],
                "status":        status,
                "finding_count": finding_count,
                "evidence_file": filepath
            })

            if rows:
                print(f"  [!] {finding_count} finding(s) detected")
            else:
                print(f"  [OK] No violations found")

        except Exception as e:
            print(f"  [ERROR] {control['id']} failed: {e}")
            results.append({
                "control_id":    control["id"],
                "name":          control["name"],
                "severity":      control["severity"],
                "framework":     control["framework"],
                "status":        "ERROR",
                "finding_count": 0,
                "evidence_file": None
            })

    connection.close()
    print(f"\n[OK] All controls complete. Evidence saved to: {evidence_dir}")

    return results
