-- M2-02 draft lifecycle: each tenant's mutable draft bundle and its class A audit trail.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role (the one
-- that ran 001). 009_draft_grants.sql gives the service role its privileges, and both tables
-- are under forced row-level security keyed on the per-transaction app.tenant_id, like the
-- policy store's (006).

CREATE TABLE IF NOT EXISTS tenant_drafts (
    tenant_id  text        PRIMARY KEY CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    -- The canonical JSON of the draft document, in a text column so no database type can
    -- rewrite it. Only a document the compiler accepted is ever written (the service checks).
    document   text        NOT NULL CHECK (octet_length(document) <= 262144),
    etag       text        NOT NULL CHECK (etag ~ '^"sha256:[0-9a-f]{64}"$'),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text        NOT NULL CHECK (updated_by <> '')
);

-- Class A events for every draft write, appended in the write's transaction (AC-A2): the actor,
-- the diff and the resulting hash. The database refuses UPDATE, DELETE and TRUNCATE.
CREATE TABLE IF NOT EXISTS tenant_draft_audit (
    id             bigserial   PRIMARY KEY,
    tenant_id      text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    at             timestamptz NOT NULL,
    -- "<issuer>#<subject>": a subject is unique only within its issuer.
    actor          text        NOT NULL CHECK (actor <> '' AND length(actor) <= 1024),
    cross_tenant   boolean     NOT NULL,
    operator       boolean     NOT NULL,
    action         text        NOT NULL
                   CHECK (action IN ('draft.put', 'draft.rule.put', 'draft.rule.delete')),
    before_hash    text        CHECK (before_hash ~ '^sha256:[0-9a-f]{64}$'),
    resulting_hash text        NOT NULL CHECK (resulting_hash ~ '^sha256:[0-9a-f]{64}$'),
    diff           jsonb       NOT NULL
);

CREATE INDEX IF NOT EXISTS tenant_draft_audit_by_tenant ON tenant_draft_audit (tenant_id, id);

CREATE OR REPLACE FUNCTION tenant_draft_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tenant_draft_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER tenant_draft_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON tenant_draft_audit
    FOR EACH ROW EXECUTE FUNCTION tenant_draft_audit_immutable();

CREATE OR REPLACE TRIGGER tenant_draft_audit_no_truncate
    BEFORE TRUNCATE ON tenant_draft_audit
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_draft_audit_immutable();

-- Tenant isolation in the database itself (see 006).
ALTER TABLE tenant_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_drafts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_drafts;
CREATE POLICY tenant_scope ON tenant_drafts
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_draft_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_draft_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_draft_audit;
CREATE POLICY tenant_scope ON tenant_draft_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
