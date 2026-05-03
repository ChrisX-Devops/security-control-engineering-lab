-- =============================================================
-- CONTROL 06: Simultaneous Multi-Location Login Detection
-- =============================================================
-- Purpose:
--   Detect accounts successfully authenticated from two
--   different IP addresses in two different locations
--   within a 1-hour window.
--   This directly confirms active credential compromise.
--
-- How It Works:
--   Self-join identical to Control 03 but with stricter window
--   (1 hour instead of 2) and also requires different IPs
--   not just different locations.
--   Both IP and location must differ to eliminate VPN false positives.
--
-- Difference from Control 03:
--   Control 03: different locations within 2 hours
--   Control 06: different locations AND different IPs within 1 hour
--   Control 06 is stricter and produces higher-confidence findings.
--
-- Framework Mapping:
--   SOC 2     → CC6.6 (Logical access boundary enforcement)
--   ISO 27001 → A.9.4.2 (Secure log-on procedures)
--
-- Control Type: Detective
-- Severity:     CRITICAL
-- =============================================================

SELECT
    a.username,
    a.login_time        AS login_time_1,
    a.location          AS location_1,
    a.ip_address        AS ip_1,
    b.login_time        AS login_time_2,
    b.location          AS location_2,
    b.ip_address        AS ip_2,
    ROUND(
        EXTRACT(EPOCH FROM (b.login_time - a.login_time))
        / 60
    )                   AS minutes_apart
FROM  login_attempts a
JOIN  login_attempts b
      ON  a.username      = b.username
      AND b.login_time    > a.login_time
      AND b.login_time    < a.login_time + INTERVAL '1 hour'
      AND a.location     <> b.location
      AND a.ip_address   <> b.ip_address
      AND a.login_status  = 'success'
      AND b.login_status  = 'success'
ORDER BY
    a.username,
    minutes_apart;
