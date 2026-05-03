-- =============================================================
-- CONTROL 04: After-Hours Login Detection
-- =============================================================
-- Purpose:
--   Flag successful logins occurring outside business hours.
--   Business hours defined as 06:00 to 23:00.
--   Logins between 23:00 and 06:00 are flagged for review.
--
-- How It Works:
--   EXTRACT(HOUR FROM login_time) pulls the hour as a number.
--   We flag anything >= 23 (11pm onwards) OR < 6 (before 6am).
--
-- Why This Matters:
--   Legitimate users rarely access systems at 2am or 3am.
--   Attackers using stolen credentials often operate at night
--   to avoid detection by active security teams.
--   Insider threats also show after-hours patterns.
--
-- How to Read Results:
--   Each row is a suspicious login event.
--   Not every row is malicious — some users work odd hours.
--   Context matters: review against user's normal pattern.
--
-- Framework Mapping:
--   SOC 2     → CC6.1 (Logical access controls)
--   ISO 27001 → A.9.4.2 (Secure log-on procedures)
--
-- Control Type: Detective
-- Severity:     MEDIUM
-- =============================================================

SELECT
    username,
    login_time,
    ip_address,
    location,
    EXTRACT(HOUR FROM login_time)   AS login_hour
FROM  login_attempts
WHERE login_status = 'success'
  AND (
        EXTRACT(HOUR FROM login_time) >= 23
        OR
        EXTRACT(HOUR FROM login_time) < 6
      )
ORDER BY login_time;
