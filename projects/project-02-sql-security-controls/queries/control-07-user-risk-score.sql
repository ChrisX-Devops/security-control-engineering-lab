-- =============================================================
-- CONTROL 07: User Risk Scoring Dashboard
-- =============================================================
-- Purpose:
--   Aggregate all risk signals into a single score per user.
--   Allows security teams to prioritize investigation by risk.
--   Converts multiple detection signals into one actionable view.
--
-- Scoring Model:
--   Failed Login Score  (max 30 points)
--     5+ failures = 30 pts
--     3-4 failures = 20 pts
--     1-2 failures = 10 pts
--
--   After Hours Score   (max 25 points)
--     3+ after-hours logins = 25 pts
--     1-2 after-hours logins = 15 pts
--
--   Location Change Score (max 40 points)
--     2+ impossible travel pairs = 40 pts
--     1 impossible travel pair   = 25 pts
--
-- Risk Levels:
--   CRITICAL = 50 or more points
--   HIGH     = 30 to 49 points
--   MEDIUM   = 10 to 29 points
--   LOW      = 0 to 9 points
--
-- How CTEs Work Here:
--   Each WITH block is a named sub-query called a CTE.
--   Each CTE calculates one risk signal for all users.
--   The final SELECT joins all CTEs together.
--   COALESCE(score, 0) replaces NULL with 0 for users who
--   have no events in that category.
--   LEFT JOIN ensures all users appear even with score of 0.
--
-- Framework Mapping:
--   SOC 2     → CC7.1 (Threat detection systems)
--   SOC 2     → CC7.2 (Security event analysis)
--   ISO 27001 → A.12.4.1 (Event logging and analysis)
--
-- Control Type: Detective + Analytical
-- Severity:     Output drives severity of other controls
-- =============================================================

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
          ON  a.username      = b.username
          AND b.login_time    > a.login_time
          AND b.login_time    < a.login_time + INTERVAL '2 hours'
          AND a.location     <> b.location
          AND a.login_status  = 'success'
          AND b.login_status  = 'success'
    GROUP BY a.username
),

all_users AS (
    SELECT DISTINCT username
    FROM login_attempts
)

SELECT
    u.username,
    COALESCE(f.score, 0)                            AS failed_login_score,
    COALESCE(a.score, 0)                            AS after_hours_score,
    COALESCE(l.score, 0)                            AS location_change_score,
    COALESCE(f.score, 0)
        + COALESCE(a.score, 0)
        + COALESCE(l.score, 0)                      AS total_risk_score,
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
    END                                             AS risk_level
FROM            all_users               u
LEFT JOIN       failed_login_score      f ON f.username = u.username
LEFT JOIN       after_hours_score       a ON a.username = u.username
LEFT JOIN       location_change_score   l ON l.username = u.username
ORDER BY total_risk_score DESC;
