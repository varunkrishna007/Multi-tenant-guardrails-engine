-- M2-03 follow-up: an edit to an approved tool's description that is held for review
-- must not unregister the tool. The approved description stays in force (it stays in the
-- entry's own columns, status 'accepted'); the held edit waits in the ``pending_*`` columns until
-- it is approved (it replaces the description) or rejected (it is dropped).
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 015. The service role's table-level grants (016) already cover the columns.

ALTER TABLE tenant_tools
    ADD COLUMN IF NOT EXISTS pending_description text
        CHECK (length(pending_description) BETWEEN 1 AND 1000),
    ADD COLUMN IF NOT EXISTS pending_read_only boolean,
    ADD COLUMN IF NOT EXISTS pending_hash text CHECK (pending_hash ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN IF NOT EXISTS pending_reason text
        CHECK (pending_reason IN ('screening', 'vocabulary')),
    ADD COLUMN IF NOT EXISTS pending_by text
        CHECK (pending_by <> '' AND length(pending_by) <= 1024),
    ADD COLUMN IF NOT EXISTS pending_at timestamptz;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'tenant_tools_pending_together' AND conrelid = 'tenant_tools'::regclass
    ) THEN
        ALTER TABLE tenant_tools ADD CONSTRAINT tenant_tools_pending_together CHECK (
            (pending_description IS NULL) = (pending_hash IS NULL)
            AND (pending_description IS NULL) = (pending_reason IS NULL)
            AND (pending_description IS NULL) = (pending_by IS NULL)
            AND (pending_description IS NULL) = (pending_at IS NULL)
            AND (pending_description IS NULL) = (pending_read_only IS NULL)
            AND (pending_description IS NULL OR status = 'accepted')
        );
    END IF;
END
$$;
