-- =============================================================
-- CONTROL 12: Full User Compliance Dashboard
-- =============================================================
-- Purpose:
--   Single comprehensive view of every user's compliance status.
--   Combines MFA status, access review status, employment
--   status, and login behavior into one dashboard.
--   This is the report you hand to an auditor.
--
-- Framework Mapping:
--   SOC 2     → CC6.1, CC6.2, CC6.3 (Complete access control)
--   ISO 27001 → A.9.2.1 through A.9.2.6 (Access management)
--
-- Control Type: Analytical
-- =============================================================

SELECT
    u.username,
    u.full_name,
    u.department,
    u.role_level,
    u.employment_status,
    CASE WHEN u.mfa_enrolled THEN 'YES' ELSE 'NO' END  AS mfa_status,
    u.last_access_review,
    CASE
        WHEN u.last_access_review IS NULL
        THEN 'NEVER REVIEWED'
        WHEN CURRENT_DATE - u.last_access_review > 90
        THEN 'OVERDUE'
        ELSE 'CURRENT'
    END                                                 AS review_status,
    COUNT(la.id)                                        AS total_login_events,
    SUM(CASE WHEN la.login_status = 'failed'
        THEN 1 ELSE 0 END)                              AS failed_logins,
    SUM(CASE WHEN la.login_status = 'success'
        THEN 1 ELSE 0 END)                              AS successful_logins,
    CASE
        WHEN u.employment_status = 'terminated'
         AND COUNT(la.id) > 0
        THEN 'CRITICAL'
        WHEN u.mfa_enrolled = false
         AND u.employment_status = 'active'
        THEN 'HIGH'
        WHEN u.last_access_review IS NULL
        THEN 'HIGH'
        WHEN CURRENT_DATE - u.last_access_review > 90
        THEN 'MEDIUM'
        ELSE 'COMPLIANT'
    END                                                 AS compliance_status
FROM  users u
LEFT JOIN login_attempts la
      ON la.username = u.username
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
    END;
