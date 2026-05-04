-- =============================================================
-- CONTROL 10: Access Review Overdue Detection
-- =============================================================
-- Purpose:
--   Find active users whose last access review was more than
--   90 days ago, or who have never been reviewed (NULL).
--   SOC2 requires periodic access reviews, typically quarterly.
--
-- How It Works:
--   For each active user, calculate the number of days since
--   their last access review.
--   Flag anyone over 90 days or with a NULL review date.
--
-- What CURRENT_DATE - last_access_review Does:
--   CURRENT_DATE is today's date.
--   Subtracting a date from another date in PostgreSQL
--   gives you the number of days between them.
--   Example: 2026-05-03 - 2025-12-01 = 153 days
--
-- Why NULL Review Dates Are Critical:
--   NULL means the user has NEVER been reviewed.
--   This is worse than an overdue review because there
--   is no evidence that anyone ever verified this user's
--   access is appropriate.
--
-- Framework Mapping:
--   SOC 2     → CC6.2 (Credential management)
--   SOC 2     → CC6.3 (Authorization verification)
--   ISO 27001 → A.9.2.5 (Review of user access rights)
--
-- Control Type: Detective
-- Severity:     HIGH (overdue) / CRITICAL (never reviewed)
-- =============================================================

SELECT
    u.username,
    u.full_name,
    u.department,
    u.role_level,
    u.last_access_review,
    CASE
        WHEN u.last_access_review IS NULL
        THEN NULL
        ELSE CURRENT_DATE - u.last_access_review
    END                                     AS days_since_review,
    CASE
        WHEN u.last_access_review IS NULL
        THEN 'CRITICAL — NEVER REVIEWED'
        WHEN CURRENT_DATE - u.last_access_review > 90
        THEN 'HIGH — OVERDUE'
        ELSE 'OK'
    END                                     AS review_status
FROM  users u
WHERE u.employment_status = 'active'
  AND (
        u.last_access_review IS NULL
        OR CURRENT_DATE - u.last_access_review > 90
      )
ORDER BY
    days_since_review DESC NULLS FIRST;
