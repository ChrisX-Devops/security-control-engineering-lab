-- =============================================================
-- CONTROL 09: MFA Enrollment Compliance Check
-- =============================================================
-- Purpose:
--   Find active users who do not have MFA enrolled.
--   SOC2 CC6.1 requires MFA for system access.
--   Any active user without MFA is a compliance violation.
--
-- How It Works:
--   Query the users table directly.
--   Filter for active users with mfa_enrolled = false.
--   Show their role level to assess severity.
--   Admin and engineer roles without MFA are CRITICAL.
--   Analyst and viewer roles without MFA are HIGH.
--
-- What the CASE WHEN Does Here:
--   It assigns a severity level based on the user's role.
--   An admin without MFA is more dangerous than a viewer
--   without MFA because the admin has more access.
--   The CASE WHEN captures this logic in the query output.
--
-- Framework Mapping:
--   SOC 2     → CC6.1 (Logical access security)
--   ISO 27001 → A.9.4.2 (Secure log-on procedures)
--
-- Control Type: Detective
-- Severity:     CRITICAL for admin/engineer, HIGH for others
-- =============================================================

SELECT
    u.username,
    u.full_name,
    u.department,
    u.role_level,
    u.employment_status,
    u.mfa_enrolled,
    CASE
        WHEN u.role_level IN ('admin', 'engineer')
        THEN 'CRITICAL'
        ELSE 'HIGH'
    END                     AS finding_severity,
    COUNT(la.id)            AS total_login_events
FROM  users u
LEFT JOIN login_attempts la
      ON  la.username = u.username
WHERE u.employment_status = 'active'
  AND u.mfa_enrolled = false
GROUP BY
    u.username, u.full_name, u.department,
    u.role_level, u.employment_status, u.mfa_enrolled
ORDER BY
    finding_severity,
    total_login_events DESC;
