-- M2-06 golden sets: a tenant's labelled examples, immutable once uploaded, and the class A
-- trail of uploads.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role.
-- 011_golden_grants.sql gives the service role its privileges. All three tables are under
-- forced row-level security keyed on the per-transaction app.tenant_id (see 006).

CREATE TABLE IF NOT EXISTS tenant_golden_sets (
    tenant_id  text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    set_id     text        NOT NULL CHECK (set_id ~ '^gs_[0-9a-f]{16}$'),
    name       text        NOT NULL CHECK (name ~ '^[A-Za-z0-9 ._-]{1,80}$'),
    set_hash   text        NOT NULL CHECK (set_hash ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    created_by text        NOT NULL CHECK (created_by <> '' AND length(created_by) <= 1024),
    counts     jsonb       NOT NULL,
    -- The quarantined rows, as [{"id": ..., "views": [...]}]: rows that tripped the harm
    -- vocabulary check. They are stored but never sent to the model (decided 2026-11-17).
    quarantine jsonb       NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (tenant_id, set_id)
);

-- One row per example. The set's examples never change: the table refuses UPDATE and DELETE.
CREATE TABLE IF NOT EXISTS tenant_golden_examples (
    tenant_id    text    NOT NULL,
    set_id       text    NOT NULL,
    position     integer NOT NULL CHECK (position >= 0),
    example_id   text    NOT NULL CHECK (example_id <> '' AND length(example_id) <= 64),
    guard_point  text    NOT NULL
                 CHECK (guard_point IN ('input', 'plan', 'tool_call', 'tool_result', 'output')),
    label        text    NOT NULL CHECK (label IN ('allow', 'block')),
    content      text    NOT NULL CHECK (content <> '' AND length(content) <= 20000),
    -- The tripwire views that matched; empty for a row that may be sent.
    quarantine   text[]  NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, set_id, position),
    UNIQUE (tenant_id, set_id, example_id),
    FOREIGN KEY (tenant_id, set_id) REFERENCES tenant_golden_sets (tenant_id, set_id)
);

CREATE TABLE IF NOT EXISTS tenant_golden_audit (
    id           bigserial   PRIMARY KEY,
    tenant_id    text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    at           timestamptz NOT NULL,
    actor        text        NOT NULL CHECK (actor <> '' AND length(actor) <= 1024),
    cross_tenant boolean     NOT NULL,
    operator     boolean     NOT NULL,
    set_id       text        NOT NULL,
    set_hash     text        NOT NULL CHECK (set_hash ~ '^sha256:[0-9a-f]{64}$'),
    examples     integer     NOT NULL CHECK (examples >= 1),
    quarantined  integer     NOT NULL DEFAULT 0 CHECK (quarantined >= 0)
);

CREATE INDEX IF NOT EXISTS tenant_golden_audit_by_tenant ON tenant_golden_audit (tenant_id, id);

CREATE OR REPLACE FUNCTION tenant_golden_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER tenant_golden_sets_immutable
    BEFORE UPDATE OR DELETE ON tenant_golden_sets
    FOR EACH ROW EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_golden_examples_immutable
    BEFORE UPDATE OR DELETE ON tenant_golden_examples
    FOR EACH ROW EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_golden_audit_immutable
    BEFORE UPDATE OR DELETE ON tenant_golden_audit
    FOR EACH ROW EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_golden_sets_no_truncate
    BEFORE TRUNCATE ON tenant_golden_sets
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_golden_examples_no_truncate
    BEFORE TRUNCATE ON tenant_golden_examples
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_golden_audit_no_truncate
    BEFORE TRUNCATE ON tenant_golden_audit
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_golden_immutable();

-- Tenant isolation in the database itself.
ALTER TABLE tenant_golden_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_golden_sets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_golden_sets;
CREATE POLICY tenant_scope ON tenant_golden_sets
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_golden_examples ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_golden_examples FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_golden_examples;
CREATE POLICY tenant_scope ON tenant_golden_examples
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_golden_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_golden_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_golden_audit;
CREATE POLICY tenant_scope ON tenant_golden_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
