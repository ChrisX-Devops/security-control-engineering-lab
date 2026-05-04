-- =============================================================
-- SEED DATA: Users Table
-- Purpose: Define user profiles with embedded policy violations
--
-- Violations embedded:
--
--   VIOLATION 1 — charlie is terminated but has login attempts
--     charlie was terminated on 2026-04-15
--     but has failed logins on 2026-05-01 and 2026-05-02
--     this means either:
--       a) his account was not disabled after termination
--       b) someone is using his credentials
--     CRITICAL finding for SOC2 CC6.2
--
--   VIOLATION 2 — diana is a viewer but logs in after hours
--     diana has role_level 'viewer' (lowest privilege)
--     viewers should not need after-hours access
--     this is a policy concern requiring review
--
--   VIOLATION 3 — eve has no MFA enrolled
--     eve is an engineer with no MFA
--     SOC2 CC6.1 requires MFA for all users
--     especially engineers who access production systems
--
--   VIOLATION 4 — alice access review is overdue
--     alice last access review was 2025-12-01
--     that is over 150 days ago
--     SOC2 requires review every 90 days
--
--   VIOLATION 5 — admin account has no last_access_review
--     admin accounts should be reviewed most frequently
--     NULL review date means it was never reviewed
--     CRITICAL finding
--
--   CLEAN USER — bob has no violations
--     active, MFA enrolled, recent access review
--     bob is what compliance looks like
-- =============================================================

INSERT INTO users
    (username, full_name, department, role_level,
     employment_status, mfa_enrolled, last_access_review,
     hire_date, termination_date)
VALUES

-- BOB: Clean baseline — fully compliant user
('bob',
 'Bob Williams',
 'Engineering',
 'engineer',
 'active',
 true,
 '2026-04-01',
 '2024-01-15',
 NULL),

-- ALICE: Active but access review overdue
('alice',
 'Alice Chen',
 'Engineering',
 'engineer',
 'active',
 true,
 '2025-12-01',
 '2023-06-01',
 NULL),

-- CHARLIE: Terminated but still has login attempts
('charlie',
 'Charlie Weber',
 'Finance',
 'analyst',
 'terminated',
 false,
 '2026-01-15',
 '2024-03-01',
 '2026-04-15'),

-- ADMIN: Shared admin account with no access review
('admin',
 'System Administrator',
 'IT Operations',
 'admin',
 'active',
 true,
 NULL,
 '2023-01-01',
 NULL),

-- DIANA: Viewer with after-hours access pattern
('diana',
 'Diana Okafor',
 'Marketing',
 'viewer',
 'active',
 true,
 '2026-03-15',
 '2025-01-10',
 NULL),

-- EVE: Engineer without MFA
('eve',
 'Eve Martinez',
 'Engineering',
 'engineer',
 'active',
 false,
 '2026-02-01',
 '2025-06-01',
 NULL);
