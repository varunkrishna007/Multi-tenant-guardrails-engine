-- M7-11: a platform operator can hold the decision provider degraded and lift the hold. Both
-- are class A events in platform_audit, so the table's action list gains two names. The table
-- stays append-only (its triggers are untouched); only the CHECK on the action column changes.
ALTER TABLE platform_audit DROP CONSTRAINT IF EXISTS platform_audit_action_check;
ALTER TABLE platform_audit ADD CONSTRAINT platform_audit_action_check CHECK (action IN (
    'release_proposed', 'release_approved', 'released', 'halt', 'resume',
    'repin', 'promote', 'raise_minimum',
    'provider_degraded_hold', 'provider_degraded_lift'));
