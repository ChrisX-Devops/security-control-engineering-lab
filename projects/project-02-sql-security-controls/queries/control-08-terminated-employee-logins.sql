-- =============================================================
-- CONTROL 08: Terminated Employee Login Detection
-- =============================================================
-- Purpose:
--   Find login attempts by employees whose employment_status
--   is 'terminated'. Any login activity after termination
--   is a critical security incident.
--
-- How It Works:
--   JOIN the login_attempts table with the users table
--   on the username column.
--   Filter for users where employment_status = 'terminated'.
--   Show all their login activity regardless of success/failure.
--
-- What a JOIN Does (simple explanation):
--   The login_attempts table has login events.
--   The users table has employee information.
--   They share the 'username' column.
--   JOIN combines them so each login event row gets
--   the employee information attached to it.
--
--   Without JOIN: you see "charlie failed login at 11am"
--   With JOIN: you see "charlie (terminated, Finance dept)
--              failed login at 11am"
--
-- Why This Matters:
--   When an employee is terminated, their access must be
--   revoked immediately. If login attempts still appear,
--   either:
--     a) Account was not disabled (process failure)
--     b) Credentials were stolen (security incident)
--   Both are critical audit findings.
--
-- Framework Mapping:
--   SOC 2     → CC6.2 (Credential lifecycle management)
--   SOC 2     → CC6.3 (Access revocation upon termination)
--   ISO 27001 → A.9.2.6 (Removal of access rights)
--
-- Control Type: Detective
-- Severity:     CRITICAL
-- =============================================================

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
    END                     AS finding_type
FROM  login_attempts la
JOIN  users u
      ON  la.username = u.username
WHERE u.employment_status = 'terminated'
ORDER BY la.login_time;
