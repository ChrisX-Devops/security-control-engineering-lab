-- =============================================================
-- SECURITY CONTROL ENGINEERING LAB
-- Project 02: SQL Security Control Validator
-- File: schema/create_users_table.sql
-- Purpose: Create the users table that stores employee
--          attributes for cross-referencing with login behavior
--
-- Why This Table Exists:
--   Login events tell us WHAT happened.
--   This table tells us WHO the person is.
--   By joining them, we can answer:
--     "Was this person authorized to do what they did?"
--
-- How Auditors Use This:
--   SOC2 CC6.2 requires proof that credentials are managed.
--   SOC2 CC6.3 requires proof that access is authorized.
--   This table provides the baseline data for both.
-- =============================================================

CREATE TABLE IF NOT EXISTS users (
    username            VARCHAR(100) PRIMARY KEY,
    full_name           VARCHAR(200)    NOT NULL,
    department          VARCHAR(100)    NOT NULL,
    role_level          VARCHAR(20)     NOT NULL
                        CHECK (role_level IN ('admin', 'engineer', 'analyst', 'viewer')),
    employment_status   VARCHAR(20)     NOT NULL
                        CHECK (employment_status IN ('active', 'terminated', 'suspended')),
    mfa_enrolled        BOOLEAN         NOT NULL DEFAULT false,
    last_access_review  DATE,
    hire_date           DATE            NOT NULL,
    termination_date    DATE
);

-- =============================================================
-- Column explanations:
--
-- username:           matches the username column in login_attempts
--                     this is how we JOIN the two tables
--
-- full_name:          human-readable name for reports
--
-- department:         which team they belong to
--                     used to detect cross-department access
--
-- role_level:         their authorized privilege level
--                     admin > engineer > analyst > viewer
--
-- employment_status:  are they still employed?
--                     terminated users should have zero logins
--
-- mfa_enrolled:       do they have MFA set up?
--                     SOC2 CC6.1 requires MFA for privileged users
--
-- last_access_review: when was their access last reviewed?
--                     SOC2 requires quarterly reviews (every 90 days)
--
-- hire_date:          when they started
--                     used to detect access before employment
--
-- termination_date:   when they were terminated (NULL if active)
--                     any login after this date is a critical finding
-- =============================================================
