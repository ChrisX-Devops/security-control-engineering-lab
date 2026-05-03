-- =============================================================
-- SEED DATA DAY 10
-- Additional records for advanced control testing
--
-- New patterns added:
--
--   PATTERN E — Impossible Travel (admin)
--     Extended: adds Lagos login 7 hours after Singapore
--     Three countries in one day
--
--   PATTERN F — After Hours (diana)
--     Legitimate user logging in at 2am, 3am, 11pm
--     Suspicious timing pattern
--
--   PATTERN G — Location Drift (eve)
--     Last login was Chicago 31 days ago
--     Now logging in from Tehran
--     Same user, very different location
--
--   PATTERN H — Extended Brute Force (alice)
--     4 more failures from Moscow on Day 2
--     Pattern continues across multiple days
-- =============================================================

INSERT INTO login_attempts
    (username, login_time, ip_address, login_status, location)
VALUES

-- ALICE: Day 2 continued brute force
('alice', '2026-05-02 08:00:00', '192.168.1.10', 'success', 'New York, USA'),
('alice', '2026-05-02 08:05:00', '45.33.22.11',  'failed',  'Moscow, Russia'),
('alice', '2026-05-02 08:05:30', '45.33.22.11',  'failed',  'Moscow, Russia'),
('alice', '2026-05-02 08:06:00', '45.33.22.11',  'failed',  'Moscow, Russia'),
('alice', '2026-05-02 08:06:30', '45.33.22.11',  'failed',  'Moscow, Russia'),
('alice', '2026-05-02 08:07:00', '45.33.22.11',  'success', 'Moscow, Russia'),

-- BOB: More clean baseline data
('bob', '2026-05-02 09:00:00', '192.168.1.11', 'success', 'London, UK'),
('bob', '2026-05-02 13:00:00', '192.168.1.11', 'success', 'London, UK'),
('bob', '2026-05-02 17:00:00', '192.168.1.11', 'success', 'London, UK'),

-- CHARLIE: More failures, still never succeeds
('charlie', '2026-05-02 10:00:00', '172.16.0.20', 'failed', 'Berlin, Germany'),
('charlie', '2026-05-02 10:01:00', '172.16.0.20', 'failed', 'Berlin, Germany'),
('charlie', '2026-05-02 10:02:00', '172.16.0.20', 'failed', 'Berlin, Germany'),

-- ADMIN: Three countries in one day (impossible travel extended)
('admin', '2026-05-02 07:00:00', '10.0.0.5',     'success', 'San Francisco, USA'),
('admin', '2026-05-02 07:45:00', '203.0.113.50',  'success', 'Singapore'),
('admin', '2026-05-02 14:00:00', '198.51.100.20', 'success', 'Lagos, Nigeria'),

-- DIANA: After-hours login pattern
('diana', '2026-05-02 02:15:00', '10.0.0.99', 'success', 'New York, USA'),
('diana', '2026-05-02 03:30:00', '10.0.0.99', 'success', 'New York, USA'),
('diana', '2026-05-02 23:45:00', '10.0.0.99', 'success', 'New York, USA'),

-- EVE: Location drift (old location vs new location)
('eve', '2026-04-01 09:00:00', '192.168.1.50', 'success', 'Chicago, USA'),
('eve', '2026-05-02 09:00:00', '91.108.4.1',   'success', 'Tehran, Iran');
