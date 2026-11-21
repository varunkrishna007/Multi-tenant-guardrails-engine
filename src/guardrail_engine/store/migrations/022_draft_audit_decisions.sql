-- M4-01: the draft audit event can carry a threshold decision, so that a
-- tenant's accept or override of a calibration suggestion is recorded in the same transaction as
-- the draft write it caused.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after 008.
-- ``detail`` is set only by the threshold route: the decisions (rule, accept or override, the
-- suggestion, the previous and applied thresholds, the targets). The table stays append-only.

ALTER TABLE tenant_draft_audit ADD COLUMN IF NOT EXISTS detail jsonb;

ALTER TABLE tenant_draft_audit DROP CONSTRAINT IF EXISTS tenant_draft_audit_action_check;
ALTER TABLE tenant_draft_audit ADD CONSTRAINT tenant_draft_audit_action_check
    CHECK (action IN ('draft.put', 'draft.rule.put', 'draft.rule.delete', 'draft.thresholds'));
