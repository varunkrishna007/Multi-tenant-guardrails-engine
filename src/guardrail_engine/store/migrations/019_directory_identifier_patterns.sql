-- M3-01 wiring: each tenant's registered cross-tenant identifier patterns.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 004. The directory's service roles already hold table-level privileges on ``tenants`` (005),
-- so the new column needs no grant: the reader role reads it, the writer role writes it.
--
-- The patterns are RE2 regular expressions that the floor's cross-tenant scan looks for in
-- every OTHER tenant's content, so they are platform-reviewed: the operator write path
-- validates them (deterministic.identifiers.validate_tenant_identifier_patterns) before they
-- are stored, and the scan validates them again when it reads them. The database holds only
-- the shape limits.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS identifier_patterns text[] NOT NULL DEFAULT '{}';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'tenants_identifier_patterns_bounded'
          AND conrelid = 'tenants'::regclass
    ) THEN
        ALTER TABLE tenants ADD CONSTRAINT tenants_identifier_patterns_bounded
            CHECK (cardinality(identifier_patterns) <= 20
                   AND array_position(identifier_patterns, NULL) IS NULL
                   AND array_position(identifier_patterns, '') IS NULL);
    END IF;
END
$$;
