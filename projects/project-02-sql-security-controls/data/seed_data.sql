-- =============================================================
-- SECURITY CONTROL ENGINEERING LAB
-- Project 02: SQL Security Control Validator
-- File: data/seed_data.sql
-- Purpose: Insert realistic authentication log data
--          with embedded threat patterns for control testing
--
-- Threat patterns embedded:
--
--   PATTERN A — Brute Force (alice)
--     Successful login from New York
--     Then 3 consecutive failures from Moscow same IP
--     Simulates credential stuffing or account takeover attempt
--
--   PATTERN B — Sustained Attack (charlie)
--     2 consecutive failures from Berlin
--     Never succeeds
--     Simulates attack on dormant or locked account
--
--   PATTERN C — Impossible Travel (admin)
--     Login from San Francisco at 10am
--     Login from Singapore at 12pm
--     2 hours apart across 17 flight hours
--     Simulates compromised admin credentials
--
--   PATTERN D — Clean Baseline (bob)
--     Consistent IP and location
--     All successful logins
--     Represents normal expected behavior
-- =============================================================

INSERT INTO login_attempts
    (username, login_time, ip_address, login_status, location)
VALUES

-- BOB: Clean baseline
('bob', '2026-05-01 08:20:00', '192.168.1.11', 'success', 'London, UK'),
('bob', '2026-05-01 10:30:00', '192.168.1.11', 'success', 'London, UK'),

-- ALICE: Brute force pattern
('alice', '2026-05-01 08:15:00', '192.168.1.10', 'success', 'New York, USA'),
('alice', '2026-05-01 09:00:00', '45.33.22.11',  'failed',  'Moscow, Russia'),
('alice', '2026-05-01 09:01:00', '45.33.22.11',  'failed',  'Moscow, Russia'),
('alice', '2026-05-01 09:02:00', '45.33.22.11',  'failed',  'Moscow, Russia'),

-- CHARLIE: Sustained attack
('charlie', '2026-05-01 11:00:00', '172.16.0.20', 'failed', 'Berlin, Germany'),
('charlie', '2026-05-01 11:01:00', '172.16.0.20', 'failed', 'Berlin, Germany'),

-- ADMIN: Impossible travel
('admin', '2026-05-01 10:00:00', '10.0.0.5',    'success', 'San Francisco, USA'),
('admin', '2026-05-01 12:00:00', '203.0.113.50', 'success', 'Singapore');
