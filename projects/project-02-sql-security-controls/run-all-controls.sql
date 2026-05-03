-- =============================================================
-- MULTI-CONTROL SECURITY VALIDATION SCRIPT
-- Project 02: SQL Security Control Validator
-- Run with:
--   sudo -u postgres psql security_logs -f run-all-controls.sql
-- =============================================================

\echo ''
\echo '============================================================='
\echo 'SECURITY CONTROL VALIDATION REPORT'
\echo 'Project 02 — SQL Security Control Validator'
\echo '============================================================='
\echo ''
\echo '--- CONTROL 01: Failed Login Spike Detection ---'
\echo 'Threshold: 2 or more failed attempts from same IP'
\echo 'Framework: SOC2 CC6.1 | ISO 27001 A.9.4.2'
\echo 'Severity:  HIGH'
\echo ''

SELECT
    username,
    COUNT(*)     AS failed_attempts,
    ip_address,
    location
FROM  login_attempts
WHERE login_status = 'failed'
GROUP BY username, ip_address, location
HAVING COUNT(*) >= 2
ORDER BY failed_attempts DESC;

\echo ''
\echo '--- CONTROL 02: Admin Account Activity Review ---'
\echo 'Scope:     All accounts containing admin in username'
\echo 'Framework: SOC2 CC6.2 | ISO 27001 A.9.2.3'
\echo 'Severity:  CRITICAL'
\echo ''

SELECT
    username,
    login_time,
    ip_address,
    location,
    login_status
FROM  login_attempts
WHERE username LIKE '%admin%'
ORDER BY login_time DESC;

\echo ''
\echo '--- CONTROL 03: Impossible Travel Detection ---'
\echo 'Threshold: Different locations within 2-hour window'
\echo 'Framework: SOC2 CC7.2 | ISO 27001 A.12.4.1'
\echo 'Severity:  CRITICAL'
\echo ''

SELECT
    a.username,
    a.login_time  AS first_login_time,
    a.location    AS first_location,
    b.login_time  AS second_login_time,
    b.location    AS second_location,
    ROUND(
        EXTRACT(EPOCH FROM (b.login_time - a.login_time)) / 60
    )             AS minutes_between_logins
FROM  login_attempts a
JOIN  login_attempts b
      ON  a.username     = b.username
      AND b.login_time   > a.login_time
      AND b.login_time   < a.login_time + INTERVAL '2 hours'
      AND a.location    <> b.location
      AND a.login_status = 'success'
      AND b.login_status = 'success'
ORDER BY a.username, a.login_time;

\echo ''
\echo '--- CONTROL 04: After-Hours Login Detection ---'
\echo 'Window:    11pm to 6am'
\echo 'Framework: SOC2 CC6.1 | ISO 27001 A.9.4.2'
\echo 'Severity:  MEDIUM'
\echo ''

SELECT
    username,
    login_time,
    ip_address,
    location,
    EXTRACT(HOUR FROM login_time) AS login_hour
FROM  login_attempts
WHERE login_status = 'success'
  AND (
        EXTRACT(HOUR FROM login_time) >= 23
        OR EXTRACT(HOUR FROM login_time) < 6
      )
ORDER BY login_time;

\echo ''
\echo '--- CONTROL 05: Accounts With Zero Successful Logins ---'
\echo 'Threshold: 3 or more attempts with zero successes'
\echo 'Framework: SOC2 CC6.1 | ISO 27001 A.9.2.5'
\echo 'Severity:  HIGH'
\echo ''

SELECT
    username,
    COUNT(*)                                                    AS total_attempts,
    SUM(CASE WHEN login_status = 'failed'  THEN 1 ELSE 0 END)  AS failed_count,
    SUM(CASE WHEN login_status = 'success' THEN 1 ELSE 0 END)  AS success_count,
    MIN(login_time)                                             AS first_attempt,
    MAX(login_time)                                             AS last_attempt
FROM  login_attempts
GROUP BY username
HAVING
    SUM(CASE WHEN login_status = 'success' THEN 1 ELSE 0 END) = 0
    AND COUNT(*) >= 3
ORDER BY total_attempts DESC;

\echo ''
\echo '--- CONTROL 06: Simultaneous Multi-Location Logins ---'
\echo 'Threshold: Different IP and location within 1-hour window'
\echo 'Framework: SOC2 CC6.6 | ISO 27001 A.9.4.2'
\echo 'Severity:  CRITICAL'
\echo ''

SELECT
    a.username,
    a.login_time   AS login_time_1,
    a.location     AS location_1,
    a.ip_address   AS ip_1,
    b.login_time   AS login_time_2,
    b.location     AS location_2,
    b.ip_address   AS ip_2,
    ROUND(
        EXTRACT(EPOCH FROM (b.login_time - a.login_time)) / 60
    )              AS minutes_apart
FROM  login_attempts a
JOIN  login_attempts b
      ON  a.username     = b.username
      AND b.login_time   > a.login_time
      AND b.login_time   < a.login_time + INTERVAL '1 hour'
      AND a.location    <> b.location
      AND a.ip_address  <> b.ip_address
      AND a.login_status = 'success'
      AND b.login_status = 'success'
ORDER BY a.username, minutes_apart;

\echo ''
\echo '--- CONTROL 07: User Risk Score Dashboard ---'
\echo 'Scores:    Failed logins (max 30) + After hours (max 25) + Location change (max 40)'
\echo 'Levels:    CRITICAL (50+) | HIGH (30-49) | MEDIUM (10-29) | LOW (0-9)'
\echo 'Framework: SOC2 CC7.1, CC7.2 | ISO 27001 A.12.4.1'
\echo ''

WITH failed_login_score AS (
    SELECT
        username,
        CASE
            WHEN COUNT(*) >= 5 THEN 30
            WHEN COUNT(*) >= 3 THEN 20
            WHEN COUNT(*) >= 1 THEN 10
            ELSE 0
        END AS score
    FROM  login_attempts
    WHERE login_status = 'failed'
    GROUP BY username
),
after_hours_score AS (
    SELECT
        username,
        CASE
            WHEN COUNT(*) >= 3 THEN 25
            WHEN COUNT(*) >= 1 THEN 15
            ELSE 0
        END AS score
    FROM  login_attempts
    WHERE login_status = 'success'
      AND (
            EXTRACT(HOUR FROM login_time) >= 23
            OR EXTRACT(HOUR FROM login_time) < 6
          )
    GROUP BY username
),
location_change_score AS (
    SELECT
        a.username,
        CASE
            WHEN COUNT(*) >= 2 THEN 40
            WHEN COUNT(*) >= 1 THEN 25
            ELSE 0
        END AS score
    FROM  login_attempts a
    JOIN  login_attempts b
          ON  a.username     = b.username
          AND b.login_time   > a.login_time
          AND b.login_time   < a.login_time + INTERVAL '2 hours'
          AND a.location    <> b.location
          AND a.login_status = 'success'
          AND b.login_status = 'success'
    GROUP BY a.username
),
all_users AS (
    SELECT DISTINCT username FROM login_attempts
)
SELECT
    u.username,
    COALESCE(f.score, 0)                   AS failed_login_score,
    COALESCE(a.score, 0)                   AS after_hours_score,
    COALESCE(l.score, 0)                   AS location_change_score,
    COALESCE(f.score, 0)
        + COALESCE(a.score, 0)
        + COALESCE(l.score, 0)             AS total_risk_score,
    CASE
        WHEN COALESCE(f.score, 0)
           + COALESCE(a.score, 0)
           + COALESCE(l.score, 0) >= 50 THEN 'CRITICAL'
        WHEN COALESCE(f.score, 0)
           + COALESCE(a.score, 0)
           + COALESCE(l.score, 0) >= 30 THEN 'HIGH'
        WHEN COALESCE(f.score, 0)
           + COALESCE(a.score, 0)
           + COALESCE(l.score, 0) >= 10 THEN 'MEDIUM'
        ELSE 'LOW'
    END                                    AS risk_level
FROM            all_users             u
LEFT JOIN       failed_login_score    f ON f.username = u.username
LEFT JOIN       after_hours_score     a ON a.username = u.username
LEFT JOIN       location_change_score l ON l.username = u.username
ORDER BY total_risk_score DESC;

\echo ''
\echo '============================================================='
\echo 'END OF SECURITY CONTROL VALIDATION REPORT'
\echo '============================================================='
\echo ''
