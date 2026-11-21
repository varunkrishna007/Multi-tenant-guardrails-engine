-- M1-02 policy store: immutable bundle versions and one active-version pointer per tenant.
--
-- Plain SQL, no migration framework. Safe to run more than once. Needs PostgreSQL 14 or later
-- (CREATE OR REPLACE TRIGGER). Object names are unqualified, so everything is created in the
-- first schema of the session's search_path.

CREATE TABLE IF NOT EXISTS policy_bundle_versions (
    tenant_id   text        NOT NULL CHECK (tenant_id <> ''),
    version     bigint      NOT NULL CHECK (version >= 1),
    -- The bundle document exactly as submitted, as canonical JSON text. It is text, not
    -- jsonb, on purpose: jsonb rewrites numbers (1e22 comes back as an integer), and the
    -- hash is over this document, so the bytes that were stored must be the bytes read back.
    document    text        NOT NULL,
    bundle_hash text        NOT NULL CHECK (bundle_hash ~ '^sha256:[0-9a-f]{64}$'),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version),
    -- A document can only be filed under the tenant and version it names.
    CONSTRAINT policy_bundle_versions_row_matches_document CHECK (
        jsonb_typeof(document::jsonb) = 'object'
        AND document::jsonb ->> 'tenant_id' = tenant_id
        AND jsonb_typeof(document::jsonb -> 'version') = 'number'
        AND document::jsonb ->> 'version' = version::text
    )
);

-- Stored versions are immutable. The database refuses UPDATE, DELETE and TRUNCATE itself, so
-- a bug or a hand-run statement can't rewrite history.
--
-- The role that owns the table can still disable a trigger. So the service must not connect
-- as the owner: run this file as an owner role used only for migrations, then run
-- 002_app_role_grants.sql to give the service's role the few privileges it needs. The hash
-- re-check on load is the second line of defence.
CREATE OR REPLACE FUNCTION policy_bundle_versions_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'policy_bundle_versions is immutable: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER policy_bundle_versions_no_update_or_delete
    BEFORE UPDATE OR DELETE ON policy_bundle_versions
    FOR EACH ROW EXECUTE FUNCTION policy_bundle_versions_immutable();

CREATE OR REPLACE TRIGGER policy_bundle_versions_no_truncate
    BEFORE TRUNCATE ON policy_bundle_versions
    FOR EACH STATEMENT EXECUTE FUNCTION policy_bundle_versions_immutable();

-- One pointer per tenant. The composite foreign key means a tenant's pointer can only name
-- one of that tenant's own versions.
CREATE TABLE IF NOT EXISTS policy_active_versions (
    tenant_id  text        PRIMARY KEY,
    version    bigint      NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, version) REFERENCES policy_bundle_versions (tenant_id, version)
);
