-- =============================================================
-- CONTROL 01: Failed Login Spike Detection
-- =============================================================
-- Purpose:
--   Detect brute force or credential stuffing attacks by
--   identifying users with 2 or more failed login attempts
--   from the same IP address.
--
-- How to Read Results:
--   Empty result  = no violations, control passing
--   Non-empty     = violations requiring investigation
--   Each row is one finding requiring follow-up
--
-- Framework Mapping:
--   SOC 2     → CC6.1  (Logical access controls)
--   SOC 2     → CC7.2  (Anomalous activity detection)
--   ISO 27001 → A.9.4.2 (Secure log-on procedures)
--
-- Control Type: Detective
-- Severity:     HIGH
-- =============================================================

SELECT
    username,
    COUNT(*)     AS failed_attempts,
    ip_address,
    location
FROM  login_attempts
WHERE login_status = 'failed'
GROUP BY
    username,
    ip_address,
    location
HAVING COUNT(*) >= 2
ORDER BY failed_attempts DESC;
