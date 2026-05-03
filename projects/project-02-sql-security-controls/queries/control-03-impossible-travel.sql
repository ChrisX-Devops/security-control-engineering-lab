-- =============================================================
-- CONTROL 03: Impossible Travel Detection
-- =============================================================
-- Purpose:
--   Detect accounts showing successful logins from
--   geographically distant locations within a short time
--   window. Physical travel between locations is impossible
--   in the time elapsed.
--
-- How It Works:
--   Joins the login_attempts table to itself.
--   For each user, finds pairs of successful logins where:
--     - Second login is after the first
--     - Both logins are within 2 hours of each other
--     - Locations are different
--   Each matching pair is a finding.
--
-- Why the Self-Join:
--   We need to compare two rows that belong to the same user.
--   A self-join lets us treat the same table as two separate
--   tables (aliased as "a" and "b") and compare rows within it.
--
-- How to Read Results:
--   Each row shows a pair of logins that cannot be legitimate.
--   The same person cannot be in two locations at once.
--   Each row requires immediate investigation.
--
-- Framework Mapping:
--   SOC 2     → CC7.2 (Anomalous activity detection)
--   SOC 2     → CC6.6 (Logical access boundary enforcement)
--   ISO 27001 → A.12.4.1 (Event logging)
--
-- Control Type: Detective
-- Severity:     CRITICAL
-- =============================================================

SELECT
    a.username,
    a.login_time                                        AS first_login_time,
    a.location                                          AS first_location,
    b.login_time                                        AS second_login_time,
    b.location                                          AS second_location,
    ROUND(
        EXTRACT(EPOCH FROM (b.login_time - a.login_time))
        / 60
    )                                                   AS minutes_between_logins
FROM  login_attempts a
JOIN  login_attempts b
      ON  a.username      = b.username
      AND b.login_time    > a.login_time
      AND b.login_time    < a.login_time + INTERVAL '2 hours'
      AND a.location     <> b.location
      AND a.login_status  = 'success'
      AND b.login_status  = 'success'
ORDER BY
    a.username,
    a.login_time;
