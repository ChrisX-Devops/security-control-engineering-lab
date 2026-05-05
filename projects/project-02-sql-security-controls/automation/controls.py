CONTROLS = [
    {
        "id": "CTL-01",
        "name": "Failed Login Spike Detection",
        "severity": "HIGH",
        "framework": "SOC2 CC6.1, CC7.2 | ISO A.9.4.2",
        "description": "Detects users with 2+ failed logins from same IP",
        "sql": """
            SELECT
                username,
                COUNT(*)        AS failed_attempts,
                ip_address,
                location
            FROM  login_attempts
            WHERE login_status = 'failed'
            GROUP BY username, ip_address, location
            HAVING COUNT(*) >= 2
            ORDER BY failed_attempts DESC
        """
    },
    {
        "id": "CTL-02",
        "name": "Admin Account Activity Review",
        "severity": "CRITICAL",
        "framework": "SOC2 CC6.2, CC6.3 | ISO A.9.2.3",
        "description": "Shows all login events for admin accounts",
        "sql": """
            SELECT
                username,
                login_time,
                ip_address,
                location,
                login_status
            FROM  login_attempts
            WHERE username LIKE '%admin%'
            ORDER BY login_time DESC
        """
    },
    {
        "id": "CTL-03",
        "name": "Impossible Travel Detection",
        "severity": "CRITICAL",
        "framework": "SOC2 CC7.2, CC6.6 | ISO A.12.4.1",
        "description": "Detects successful logins from different locations within 2 hours",
        "sql": """
            SELECT
                a.username,
                a.login_time    AS first_login_time,
                a.location      AS first_location,
                b.login_time    AS second_login_time,
                b.location      AS second_location,
                ROUND(
                    EXTRACT(EPOCH FROM (b.login_time - a.login_time)) / 60
                )               AS minutes_between_logins
            FROM  login_attempts a
            JOIN  login_attempts b
                  ON  a.username     = b.username
                  AND b.login_time   > a.login_time
                  AND b.login_time   < a.login_time + INTERVAL '2 hours'
                  AND a.location    <> b.location
                  AND a.login_status = 'success'
                  AND b.login_status = 'success'
            ORDER BY a.username, a.login_time
        """
    },
    {
        "id": "CTL-04",
        "name": "After-Hours Login Detection",
        "severity": "MEDIUM",
        "framework": "SOC2 CC6.1 | ISO A.9.4.2",
        "description": "Flags successful logins between 11pm and 6am",
        "sql": """
            SELECT
                username,
                login_time,
                ip_address,
                location,
                EXTRACT(HOUR FROM login_time) AS login_hour
            FROM  login_attempts
            WHERE login_status = 'success'
              AND (
                    EXTRACT(HOUR FROM login_time) >= 23
                    OR EXTRACT(HOUR FROM login_time) < 6
                  )
            ORDER BY login_time
        """
    },
    {
        "id": "CTL-05",
        "name": "Zero Success Accounts",
        "severity": "HIGH",
        "framework": "SOC2 CC6.1 | ISO A.9.2.5",
        "description": "Finds accounts with 3+ failed logins and zero successes",
        "sql": """
            SELECT
                username,
                COUNT(*)                                                    AS total_attempts,
                SUM(CASE WHEN login_status = 'failed'  THEN 1 ELSE 0 END)  AS failed_count,
                SUM(CASE WHEN login_status = 'success' THEN 1 ELSE 0 END)  AS success_count,
                MIN(login_time)                                             AS first_attempt,
                MAX(login_time)                                             AS last_attempt
            FROM  login_attempts
            GROUP BY username
            HAVING
                SUM(CASE WHEN login_status = 'success' THEN 1 ELSE 0 END) = 0
                AND COUNT(*) >= 3
            ORDER BY total_attempts DESC
        """
    },
    {
        "id": "CTL-06",
        "name": "Simultaneous Multi-Location Logins",
        "severity": "CRITICAL",
        "framework": "SOC2 CC6.6 | ISO A.9.4.2",
        "description": "Detects logins from different IPs and locations within 1 hour",
        "sql": """
            SELECT
                a.username,
                a.login_time    AS login_time_1,
                a.location      AS location_1,
                a.ip_address    AS ip_1,
                b.login_time    AS login_time_2,
                b.location      AS location_2,
                b.ip_address    AS ip_2,
                ROUND(
                    EXTRACT(EPOCH FROM (b.login_time - a.login_time)) / 60
                )               AS minutes_apart
            FROM  login_attempts a
            JOIN  login_attempts b
                  ON  a.username     = b.username
                  AND b.login_time   > a.login_time
                  AND b.login_time   < a.login_time + INTERVAL '1 hour'
                  AND a.location    <> b.location
                  AND a.ip_address  <> b.ip_address
                  AND a.login_status = 'success'
                  AND b.login_status = 'success'
            ORDER BY a.username, minutes_apart
        """
    },
    {
        "id": "CTL-07",
        "name": "User Risk Score Dashboard",
        "severity": "INFO",
        "framework": "SOC2 CC7.1, CC7.2 | ISO A.12.4.1",
        "description": "Aggregates all risk signals into a score per user",
        "sql": """
            WITH failed_login_score AS (
                SELECT username,
                    CASE
                        WHEN COUNT(*) >= 5 THEN 30
                        WHEN COUNT(*) >= 3 THEN 20
                        WHEN COUNT(*) >= 1 THEN 10
                        ELSE 0
                    END AS score
                FROM login_attempts
                WHERE login_status = 'failed'
                GROUP BY username
            ),
            after_hours_score AS (
                SELECT username,
                    CASE
                        WHEN COUNT(*) >= 3 THEN 25
                        WHEN COUNT(*) >= 1 THEN 15
                        ELSE 0
                    END AS score
                FROM login_attempts
                WHERE login_status = 'success'
                  AND (EXTRACT(HOUR FROM login_time) >= 23
                       OR EXTRACT(HOUR FROM login_time) < 6)
                GROUP BY username
            ),
            location_change_score AS (
                SELECT a.username,
                    CASE
                        WHEN COUNT(*) >= 2 THEN 40
                        WHEN COUNT(*) >= 1 THEN 25
                        ELSE 0
                    END AS score
                FROM login_attempts a
                JOIN login_attempts b
                     ON  a.username     = b.username
                     AND b.login_time   > a.login_time
                     AND b.login_time   < a.login_time + INTERVAL '2 hours'
                     AND a.location    <> b.location
                     AND a.login_status = 'success'
                     AND b.login_status = 'success'
                GROUP BY a.username
            ),
            all_users AS (
                SELECT DISTINCT username FROM login_attempts
            )
            SELECT
                u.username,
                COALESCE(f.score, 0) AS failed_login_score,
                COALESCE(a.score, 0) AS after_hours_score,
                COALESCE(l.score, 0) AS location_change_score,
                COALESCE(f.score, 0)
                    + COALESCE(a.score, 0)
                    + COALESCE(l.score, 0) AS total_risk_score,
                CASE
                    WHEN COALESCE(f.score,0)+COALESCE(a.score,0)+COALESCE(l.score,0) >= 50 THEN 'CRITICAL'
                    WHEN COALESCE(f.score,0)+COALESCE(a.score,0)+COALESCE(l.score,0) >= 30 THEN 'HIGH'
                    WHEN COALESCE(f.score,0)+COALESCE(a.score,0)+COALESCE(l.score,0) >= 10 THEN 'MEDIUM'
                    ELSE 'LOW'
                END AS risk_level
            FROM all_users u
            LEFT JOIN failed_login_score    f ON f.username = u.username
            LEFT JOIN after_hours_score     a ON a.username = u.username
            LEFT JOIN location_change_score l ON l.username = u.username
            ORDER BY total_risk_score DESC
        """
    },
    {
        "id": "CTL-08",
        "name": "Terminated Employee Login Detection",
        "severity": "CRITICAL",
        "framework": "SOC2 CC6.2, CC6.3 | ISO A.9.2.6",
        "description": "Finds login activity from terminated employees",
        "sql": """
            SELECT
                la.username,
                u.full_name,
                u.department,
                u.employment_status,
                u.termination_date,
                la.login_time,
                la.ip_address,
                la.location,
                la.login_status,
                CASE
                    WHEN la.login_time > u.termination_date
                    THEN 'POST-TERMINATION LOGIN'
                    ELSE 'PRE-TERMINATION LOGIN'
                END AS finding_type
            FROM  login_attempts la
            JOIN  users u ON la.username = u.username
            WHERE u.employment_status = 'terminated'
            ORDER BY la.login_time
        """
    },
    {
        "id": "CTL-09",
        "name": "MFA Enrollment Compliance",
        "severity": "CRITICAL",
        "framework": "SOC2 CC6.1 | ISO A.9.4.2",
        "description": "Finds active users without MFA enrolled",
        "sql": """
            SELECT
                u.username,
                u.full_name,
                u.department,
                u.role_level,
                u.mfa_enrolled,
                CASE
                    WHEN u.role_level IN ('admin', 'engineer') THEN 'CRITICAL'
                    ELSE 'HIGH'
                END AS finding_severity,
                COUNT(la.id) AS total_login_events
            FROM  users u
            LEFT JOIN login_attempts la ON la.username = u.username
            WHERE u.employment_status = 'active'
              AND u.mfa_enrolled = false
            GROUP BY
                u.username, u.full_name, u.department,
                u.role_level, u.mfa_enrolled
            ORDER BY finding_severity, total_login_events DESC
        """
    },
    {
        "id": "CTL-10",
        "name": "Access Review Overdue",
        "severity": "HIGH",
        "framework": "SOC2 CC6.2, CC6.3 | ISO A.9.2.5",
        "description": "Finds active users whose access review is overdue",
        "sql": """
            SELECT
                u.username,
                u.full_name,
                u.department,
                u.role_level,
                u.last_access_review,
                CASE
                    WHEN u.last_access_review IS NULL THEN NULL
                    ELSE CURRENT_DATE - u.last_access_review
                END AS days_since_review,
                CASE
                    WHEN u.last_access_review IS NULL THEN 'CRITICAL - NEVER REVIEWED'
                    WHEN CURRENT_DATE - u.last_access_review > 90 THEN 'HIGH - OVERDUE'
                    ELSE 'OK'
                END AS review_status
            FROM  users u
            WHERE u.employment_status = 'active'
              AND (
                    u.last_access_review IS NULL
                    OR CURRENT_DATE - u.last_access_review > 90
                  )
            ORDER BY days_since_review DESC NULLS FIRST
        """
    },
    {
        "id": "CTL-11",
        "name": "Role-Based Access Violation",
        "severity": "HIGH",
        "framework": "SOC2 CC6.3 | ISO A.9.2.3",
        "description": "Cross-references user role with login behavior",
        "sql": """
            SELECT
                u.username,
                u.full_name,
                u.department,
                u.role_level,
                u.employment_status,
                COUNT(la.id)                                                    AS total_logins,
                SUM(CASE WHEN la.login_status = 'failed' THEN 1 ELSE 0 END)    AS failed_logins,
                COUNT(DISTINCT la.location)                                     AS unique_locations,
                CASE
                    WHEN u.employment_status = 'terminated'
                    THEN 'CRITICAL - TERMINATED USER HAS LOGIN ACTIVITY'
                    WHEN u.role_level = 'viewer'
                     AND SUM(CASE
                             WHEN la.login_status = 'success'
                              AND (EXTRACT(HOUR FROM la.login_time) >= 23
                                   OR EXTRACT(HOUR FROM la.login_time) < 6)
                             THEN 1 ELSE 0 END) > 0
                    THEN 'HIGH - VIEWER WITH AFTER-HOURS ACCESS'
                    WHEN COUNT(DISTINCT la.location) > 2
                    THEN 'HIGH - ACCESS FROM MULTIPLE COUNTRIES'
                    WHEN SUM(CASE WHEN la.login_status = 'failed' THEN 1 ELSE 0 END)
                       > SUM(CASE WHEN la.login_status = 'success' THEN 1 ELSE 0 END)
                    THEN 'MEDIUM - MORE FAILURES THAN SUCCESSES'
                    ELSE 'LOW'
                END AS risk_assessment
            FROM  users u
            LEFT JOIN login_attempts la ON la.username = u.username
            GROUP BY
                u.username, u.full_name, u.department,
                u.role_level, u.employment_status
            ORDER BY total_logins DESC
        """
    },
    {
        "id": "CTL-12",
        "name": "Full User Compliance Dashboard",
        "severity": "INFO",
        "framework": "SOC2 CC6.1, CC6.2, CC6.3 | ISO A.9.2.1-A.9.2.6",
        "description": "Complete compliance posture for all users",
        "sql": """
            SELECT
                u.username,
                u.full_name,
                u.department,
                u.role_level,
                u.employment_status,
                CASE WHEN u.mfa_enrolled THEN 'YES' ELSE 'NO' END AS mfa_status,
                u.last_access_review,
                CASE
                    WHEN u.last_access_review IS NULL THEN 'NEVER REVIEWED'
                    WHEN CURRENT_DATE - u.last_access_review > 90 THEN 'OVERDUE'
                    ELSE 'CURRENT'
                END AS review_status,
                COUNT(la.id)                                        AS total_login_events,
                SUM(CASE WHEN la.login_status = 'failed'
                    THEN 1 ELSE 0 END)                              AS failed_logins,
                SUM(CASE WHEN la.login_status = 'success'
                    THEN 1 ELSE 0 END)                              AS successful_logins,
                CASE
                    WHEN u.employment_status = 'terminated'
                     AND COUNT(la.id) > 0                           THEN 'CRITICAL'
                    WHEN u.mfa_enrolled = false
                     AND u.employment_status = 'active'             THEN 'HIGH'
                    WHEN u.last_access_review IS NULL               THEN 'HIGH'
                    WHEN CURRENT_DATE - u.last_access_review > 90   THEN 'MEDIUM'
                    ELSE 'COMPLIANT'
                END AS compliance_status
            FROM  users u
            LEFT JOIN login_attempts la ON la.username = u.username
            GROUP BY
                u.username, u.full_name, u.department,
                u.role_level, u.employment_status,
                u.mfa_enrolled, u.last_access_review
            ORDER BY
                CASE
                    WHEN u.employment_status = 'terminated'
                     AND COUNT(la.id) > 0 THEN 1
                    WHEN u.mfa_enrolled = false THEN 2
                    WHEN u.last_access_review IS NULL THEN 3
                    ELSE 4
                END
        """
    }
]
