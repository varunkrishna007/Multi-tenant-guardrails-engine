-- One tenant id rule (B3): t_ then 1-32 lowercase letters or digits, for every
-- store key, so no tenant can be stored that can't authenticate. The same pattern as
-- guardrail_engine.tenant_ids.TENANT_ID_PATTERN.
--
-- Safe to run more than once. The constraint is added NOT VALID: it holds for every row
-- written from now on, and rows already stored aren't rechecked, so an older database
-- doesn't fail the migration. (Rows are immutable, so an invalid old row can't be changed;
-- its tenant could never authenticate.) The active pointer table needs no constraint of its
-- own: its foreign key names a row here.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'policy_bundle_versions_tenant_id_format'
          AND conrelid = 'policy_bundle_versions'::regclass
    ) THEN
        ALTER TABLE policy_bundle_versions
            ADD CONSTRAINT policy_bundle_versions_tenant_id_format
            CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$') NOT VALID;
    END IF;
END;
$$;
