-- =============================================================
-- SECURITY CONTROL ENGINEERING LAB
-- Project 02: SQL Security Control Validator
-- File: data/seed_data.sql
-- Purpose: Insert realistic authentication log data
--          with embedded threat patterns for testing
--
-- Threat patterns embedded in this data:
--
--   PATTERN A — Brute Force Attack (alice)
--     alice logs in successfully from New York
--     then gets 3 consecutive failures from Moscow same IP
--     this simulates credential stuffing or account takeover attempt
--
--   PATTERN B — Sustained Account Attack (charlie)
--     charlie has 2 consecutive failures from Berlin
--     never succeeds
--     simulates attack on dormant or locked account
--
--   PATTERN C — Admin Multi-Location (admin)
--     admin logs in from San Francisco at 10am
--     then logs in from Singapore at 12pm
--     2 hours apart, impossible travel
--     simulates compromised admin credentials
--
--   PATTERN D — Clean Baseline (bob)
--     bob has consistent logins from same IP and location
--     all successful
--     this is what normal behavior looks like
-- =============================================================

INSERT INTO login_attempts
    (username, login_time, ip_address, login_status, location)
VALUES

-- -------------------------------------------------------
-- BOB: Clean baseline user
-- Consistent IP, consistent location, all successes
-- -------------------------------------------------------
('bob', '2026-05-01 08:20:00', '192.168.1.11', 'success', 'London, UK'),
('bob', '2026-05-01 10:30:00', '192.168.1.11', 'success', 'London, UK'),

-- -------------------------------------------------------
-- ALICE: Brute force pattern (Pattern A)
-- Normal morning login from New York
-- Then 3 rapid failures from Moscow same IP
-- -------------------------------------------------------
('alice', '2026-05-01 08:15:00', '192.168.1.10', 'success', 'New York, USA'),
('alice', '2026-05-01 09:00:00', '45.33.22.11',  'failed',  'Moscow, Russia'),
('alice', '2026-05-01 09:01:00', '45.33.22.11',  'failed',  'Moscow, Russia'),
('alice', '2026-05-01 09:02:00', '45.33.22.11',  'failed',  'Moscow, Russia'),

-- -------------------------------------------------------
-- CHARLIE: Sustained attack (Pattern B)
-- Multiple failures, never succeeds
-- -------------------------------------------------------
('charlie', '2026-05-01 11:00:00', '172.16.0.20', 'failed', 'Berlin, Germany'),
('charlie', '2026-05-01 11:01:00', '172.16.0.20', 'failed', 'Berlin, Germany'),

-- -------------------------------------------------------
-- ADMIN: Multi-location login (Pattern C)
-- San Francisco at 10am, Singapore at 12pm
-- 2 hours apart — physically impossible travel
-- -------------------------------------------------------
('admin', '2026-05-01 10:00:00', '10.0.0.5',    'success', 'San Francisco, USA'),
('admin', '2026-05-01 12:00:00', '203.0.113.50', 'success', 'Singapore');
