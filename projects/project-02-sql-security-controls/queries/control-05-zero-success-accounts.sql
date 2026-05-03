-- =============================================================
-- CONTROL 05: Accounts With Zero Successful Logins
-- =============================================================
-- Purpose:
--   Identify accounts that have multiple failed login attempts
--   but zero successful logins in the observation period.
--   This pattern indicates a targeted account attack or
--   credential stuffing against a dormant account.
--
-- How It Works:
--   Groups all login events by username.
--   Uses CASE WHEN inside SUM to count only failed rows
--   and only successful rows separately.
--   HAVING filters to only show accounts where success = 0
--   and total attempts >= 3 (filters out single-attempt noise).
--
-- Why CASE WHEN inside SUM:
--   We cannot use WHERE to filter inside an aggregate.
--   CASE WHEN lets us count conditionally within the same query.
--   SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)
--   is the standard pattern for conditional counting in SQL.
--
-- Framework Mapping:
--   SOC 2     → CC6.1 (Logical access controls)
--   ISO 27001 → A.9.2.5 (Review of user access rights)
--
-- Control Type: Detective
-- Severity:     HIGH
-- =============================================================

SELECT
    username,
    COUNT(*)                                                        AS total_attempts,
    SUM(CASE WHEN login_status = 'failed'  THEN 1 ELSE 0 END)      AS failed_count,
    SUM(CASE WHEN login_status = 'success' THEN 1 ELSE 0 END)      AS success_count,
    MIN(login_time)                                                 AS first_attempt,
    MAX(login_time)                                                 AS last_attempt
FROM  login_attempts
GROUP BY username
HAVING
    SUM(CASE WHEN login_status = 'success' THEN 1 ELSE 0 END) = 0
    AND COUNT(*) >= 3
ORDER BY total_attempts DESC;
