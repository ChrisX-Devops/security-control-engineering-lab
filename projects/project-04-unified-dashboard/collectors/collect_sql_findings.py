"""
collect_sql_findings.py
=======================
Pulls current security findings from the SQL control
system (Project 02) and normalizes them into the
unified finding format.

Why normalize:
    Each project produces findings in slightly different
    formats. The unified dashboard needs one consistent
    format so it can combine and score everything together.

Unified finding format:
    {
        "finding_id":   unique identifier
        "source":       which project produced this
        "control_id":   control identifier
        "title":        human-readable name
        "severity":     CRITICAL / HIGH / MEDIUM / LOW
        "status":       FAIL / PASS
        "resource":     what was checked
        "description":  what was found
        "framework":    SOC2 and ISO mappings
        "category":     access_control / data_protection /
                        logging / identity
    }
"""

import psycopg2
import sys
import os
from datetime import datetime


def get_connection():
    try:
        return psycopg2.connect(
            dbname="security_logs",
            user="postgres",
            password="securelab123",
            host="localhost",
            port="5432"
        )
    except psycopg2.OperationalError as e:
        print(f"  [ERROR] Database connection failed: {e}")
        return None


def collect_sql_findings():
    """
    Run key SQL controls and return normalized findings.

    Returns:
        list: normalized finding dicts
    """
    print("  Collecting SQL security findings...")

    conn = get_connection()
    if not conn:
        return []

    findings = []
    cursor = conn.cursor()

    # Check 1: Brute force attempts
    cursor.execute("""
        SELECT username, COUNT(*) as attempts, ip_address, location
        FROM login_attempts
        WHERE login_status = 'failed'
        GROUP BY username, ip_address, location
        HAVING COUNT(*) >= 2
        ORDER BY attempts DESC
    """)
    rows = cursor.fetchall()
    for row in rows:
        findings.append({
            "finding_id":  f"SQL-BF-{row[0]}",
            "source":      "project-02-sql-controls",
            "control_id":  "CTL-01",
            "title":       "Brute Force Login Detected",
            "severity":    "HIGH",
            "status":      "FAIL",
            "resource":    f"user/{row[0]} from {row[2]}",
            "description": (
                f"User '{row[0]}' had {row[1]} failed login attempts "
                f"from {row[2]} ({row[3]})"
            ),
            "framework":   "SOC2 CC6.1, CC7.2",
            "category":    "access_control"
        })

    # Check 2: Terminated employee logins
    cursor.execute("""
        SELECT la.username, u.full_name, u.termination_date,
               COUNT(*) as login_count
        FROM login_attempts la
        JOIN users u ON la.username = u.username
        WHERE u.employment_status = 'terminated'
        GROUP BY la.username, u.full_name, u.termination_date
    """)
    rows = cursor.fetchall()
    for row in rows:
        findings.append({
            "finding_id":  f"SQL-TERM-{row[0]}",
            "source":      "project-02-sql-controls",
            "control_id":  "CTL-08",
            "title":       "Terminated Employee Login Activity",
            "severity":    "CRITICAL",
            "status":      "FAIL",
            "resource":    f"user/{row[0]}",
            "description": (
                f"Terminated employee '{row[1]}' has {row[3]} login "
                f"events after termination date {row[2]}"
            ),
            "framework":   "SOC2 CC6.2, CC6.3",
            "category":    "access_control"
        })

    # Check 3: MFA not enrolled
    cursor.execute("""
        SELECT username, full_name, role_level
        FROM users
        WHERE employment_status = 'active'
          AND mfa_enrolled = false
    """)
    rows = cursor.fetchall()
    for row in rows:
        findings.append({
            "finding_id":  f"SQL-MFA-{row[0]}",
            "source":      "project-02-sql-controls",
            "control_id":  "CTL-09",
            "title":       "Active User Without MFA",
            "severity":    "CRITICAL" if row[2] in ("admin", "engineer")
                          else "HIGH",
            "status":      "FAIL",
            "resource":    f"user/{row[0]}",
            "description": (
                f"User '{row[1]}' ({row[2]}) is active but has "
                f"no MFA device enrolled"
            ),
            "framework":   "SOC2 CC6.1",
            "category":    "identity"
        })

    # Check 4: Access review overdue
    cursor.execute("""
        SELECT username, full_name, last_access_review,
               CURRENT_DATE - last_access_review as days_overdue
        FROM users
        WHERE employment_status = 'active'
          AND (last_access_review IS NULL
               OR CURRENT_DATE - last_access_review > 90)
    """)
    rows = cursor.fetchall()
    for row in rows:
        days = row[3] if row[3] else "Never reviewed"
        findings.append({
            "finding_id":  f"SQL-REV-{row[0]}",
            "source":      "project-02-sql-controls",
            "control_id":  "CTL-10",
            "title":       "Access Review Overdue",
            "severity":    "CRITICAL" if row[2] is None else "HIGH",
            "status":      "FAIL",
            "resource":    f"user/{row[0]}",
            "description": (
                f"User '{row[1]}' access review is overdue. "
                f"Days since last review: {days}"
            ),
            "framework":   "SOC2 CC6.2, CC6.3",
            "category":    "access_control"
        })

    # Check 5: After-hours logins
    cursor.execute("""
        SELECT username, COUNT(*) as count
        FROM login_attempts
        WHERE login_status = 'success'
          AND (EXTRACT(HOUR FROM login_time) >= 23
               OR EXTRACT(HOUR FROM login_time) < 6)
        GROUP BY username
        HAVING COUNT(*) >= 2
    """)
    rows = cursor.fetchall()
    for row in rows:
        findings.append({
            "finding_id":  f"SQL-AH-{row[0]}",
            "source":      "project-02-sql-controls",
            "control_id":  "CTL-04",
            "title":       "Repeated After-Hours Login Activity",
            "severity":    "MEDIUM",
            "status":      "FAIL",
            "resource":    f"user/{row[0]}",
            "description": (
                f"User '{row[0]}' has {row[1]} successful logins "
                f"between 11pm and 6am"
            ),
            "framework":   "SOC2 CC6.1",
            "category":    "access_control"
        })

    cursor.close()
    conn.close()

    print(f"  Found {len(findings)} SQL findings")
    return findings
