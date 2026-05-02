-- =============================================================
-- CONTROL 02: Admin Account Activity Review
-- =============================================================
-- Purpose:
--   Monitor all authentication events for privileged accounts.
--   Every admin login must be logged and reviewable.
--   Generates the complete admin activity trail for auditors.
--
-- How to Read Results:
--   Every row is an admin login event
--   Review each row against the checklist below
--   Flag unexpected locations or times for investigation
--
-- Review Checklist For Each Row:
--   Is this a known admin user?
--   Is the IP address expected?
--   Is the location consistent with where this person works?
--   Was a change management ticket open at this time?
--
-- Framework Mapping:
--   SOC 2     → CC6.2  (Credential management)
--   SOC 2     → CC6.3  (Authorization enforcement)
--   ISO 27001 → A.9.2.3 (Privileged access rights)
--   ISO 27001 → A.9.4.2 (Secure log-on procedures)
--
-- Control Type: Detective
-- Severity:     CRITICAL
-- =============================================================

SELECT
    username,
    login_time,
    ip_address,
    location,
    login_status
FROM  login_attempts
WHERE username LIKE '%admin%'
ORDER BY login_time DESC;
