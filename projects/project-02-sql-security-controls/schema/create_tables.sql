-- =============================================================
-- SECURITY CONTROL ENGINEERING LAB
-- Project 02: SQL Security Control Validator
-- File: schema/create_tables.sql
-- Purpose: Create the login_attempts table and performance
--          indexes for security control detection queries
-- =============================================================

CREATE TABLE IF NOT EXISTS login_attempts (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(100)    NOT NULL,
    login_time      TIMESTAMP       NOT NULL,
    ip_address      VARCHAR(50),
    login_status    VARCHAR(20)     CHECK (login_status IN ('success', 'failed')),
    location        VARCHAR(100)
);

-- Index on username
-- Controls frequently filter by username
CREATE INDEX IF NOT EXISTS idx_login_username
    ON login_attempts (username);

-- Index on login_time
-- Controls frequently filter by time window
CREATE INDEX IF NOT EXISTS idx_login_time
    ON login_attempts (login_time);

-- Index on login_status
-- Controls frequently separate failed vs success events
CREATE INDEX IF NOT EXISTS idx_login_status
    ON login_attempts (login_status);
