-- M2-01 tenant directory: platform-owned tenant records and their audit trail.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role (the one
-- that ran 001); 005_directory_grants.sql then gives the service roles their privileges.
--
-- Not row-level-secured on purpose: this is platform data (the Guard Service reads any tenant's
-- record by id; only platform operators write). Tenant-scoped data (policy bundles) is what
-- 006 puts under RLS.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id      text        PRIMARY KEY CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    -- Assigned by platform ops as a reviewed step. The instruction-like-token denylist is
    -- enforced in code (directory.model) at write and again when a profile is built.
    slug           text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{1,40}$'),
    domain         text        NOT NULL
                   CHECK (domain IN ('insurance', 'energy', 'finance', 'healthcare', 'general')),
    tier           text        NOT NULL CHECK (tier IN ('standard', 'regulated', 'dedicated')),
    flags          text[]      NOT NULL DEFAULT '{}'
                   CHECK (flags <@ ARRAY['two_person_publish']::text[]),
    required_packs text[]      NOT NULL DEFAULT '{}',
    baa            boolean     NOT NULL DEFAULT false,
    status         text        NOT NULL CHECK (status IN ('active', 'suspended', 'offboarded')),
    version        bigint      NOT NULL CHECK (version >= 1),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Class A audit events for every directory write, appended in the write's transaction. The
-- database refuses UPDATE, DELETE and TRUNCATE, like the policy store's versions.
CREATE TABLE IF NOT EXISTS tenant_directory_audit (
    id        bigserial   PRIMARY KEY,
    tenant_id text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    version   bigint      NOT NULL CHECK (version >= 1),
    action    text        NOT NULL CHECK (action IN ('create', 'update', 'set_status')),
    actor     text        NOT NULL CHECK (actor <> ''),
    at        timestamptz NOT NULL,
    before    jsonb,
    after     jsonb       NOT NULL
);

CREATE INDEX IF NOT EXISTS tenant_directory_audit_by_tenant
    ON tenant_directory_audit (tenant_id, id);

CREATE OR REPLACE FUNCTION tenant_directory_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tenant_directory_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER tenant_directory_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON tenant_directory_audit
    FOR EACH ROW EXECUTE FUNCTION tenant_directory_audit_immutable();

CREATE OR REPLACE TRIGGER tenant_directory_audit_no_truncate
    BEFORE TRUNCATE ON tenant_directory_audit
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_directory_audit_immutable();
