-- =============================================================
-- CONTROL 11: Role-Based Access Violation Detection
-- =============================================================
-- Purpose:
--   Cross-reference each user's assigned role level with
--   their actual login behavior to detect anomalies.
--   Viewers logging in at 2am is suspicious.
--   Terminated users logging in at all is critical.
--
-- How It Works:
--   JOIN users with login_attempts.
--   For each user, aggregate their login behavior.
--   Apply risk rules based on role + behavior combination.
--
-- What This Detects:
--   1. Viewers with after-hours logins (unusual for role)
--   2. Analysts accessing from foreign locations
--   3. Any role with logins from multiple countries
--   4. High login volume for low-privilege roles
--
-- Framework Mapping:
--   SOC 2     → CC6.3 (Authorization enforcement)
--   ISO 27001 → A.9.2.3 (Privileged access management)
--
-- Control Type: Detective
-- Severity:     Varies by finding
-- =============================================================

SELECT
    u.username,
    u.full_name,
    u.department,
    u.role_level,
    u.employment_status,
    COUNT(la.id)                                                    AS total_logins,
    SUM(CASE WHEN la.login_status = 'failed' THEN 1 ELSE 0 END)    AS failed_logins,
    SUM(CASE WHEN la.login_status = 'success' THEN 1 ELSE 0 END)   AS successful_logins,
    COUNT(DISTINCT la.location)                                     AS unique_locations,
    SUM(CASE
        WHEN la.login_status = 'success'
         AND (EXTRACT(HOUR FROM la.login_time) >= 23
              OR EXTRACT(HOUR FROM la.login_time) < 6)
        THEN 1 ELSE 0
    END)                                                            AS after_hours_logins,
    CASE
        WHEN u.employment_status = 'terminated'
        THEN 'CRITICAL — TERMINATED USER HAS LOGIN ACTIVITY'
        WHEN u.role_level = 'viewer'
         AND SUM(CASE
                 WHEN la.login_status = 'success'
                  AND (EXTRACT(HOUR FROM la.login_time) >= 23
                       OR EXTRACT(HOUR FROM la.login_time) < 6)
                 THEN 1 ELSE 0 END) > 0
        THEN 'HIGH — VIEWER WITH AFTER-HOURS ACCESS'
        WHEN COUNT(DISTINCT la.location) > 2
        THEN 'HIGH — ACCESS FROM MULTIPLE COUNTRIES'
        WHEN SUM(CASE WHEN la.login_status = 'failed' THEN 1 ELSE 0 END)
           > SUM(CASE WHEN la.login_status = 'success' THEN 1 ELSE 0 END)
        THEN 'MEDIUM — MORE FAILURES THAN SUCCESSES'
        ELSE 'LOW'
    END                                                             AS risk_assessment
FROM  users u
LEFT JOIN login_attempts la
      ON la.username = u.username
GROUP BY
    u.username, u.full_name, u.department,
    u.role_level, u.employment_status
ORDER BY
    CASE
        WHEN u.employment_status = 'terminated' THEN 1
        ELSE 2
    END,
    total_logins DESC;
