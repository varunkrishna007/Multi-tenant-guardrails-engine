-- M2-03 the tenant tool registry and its class A trail.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role.
-- 016_tool_grants.sql gives the service role its privileges. Both tables are under forced
-- row-level security keyed on the per-transaction app.tenant_id (see 006).

-- One row per tool. ``status`` is ``accepted`` (in the tenant's profile), ``held`` (waiting for
-- a reviewer; ``hold_reason`` says why) or ``rejected`` (a reviewer refused it). A description that
-- screening blocks is never stored here: only a class A row records the attempt.
CREATE TABLE IF NOT EXISTS tenant_tools (
    tenant_id        text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    name             text        NOT NULL CHECK (name ~ '^[a-z0-9_.-]{1,64}$'),
    description      text        NOT NULL CHECK (length(description) BETWEEN 1 AND 1000),
    read_only        boolean     NOT NULL,
    status           text        NOT NULL CHECK (status IN ('accepted', 'held', 'rejected')),
    hold_reason      text        CHECK (hold_reason IN ('screening', 'vocabulary')),
    description_hash text        NOT NULL CHECK (description_hash ~ '^sha256:[0-9a-f]{64}$'),
    submitted_by     text        NOT NULL CHECK (submitted_by <> '' AND length(submitted_by) <= 1024),
    submitted_at     timestamptz NOT NULL,
    reviewed_by      text        CHECK (reviewed_by <> '' AND length(reviewed_by) <= 1024),
    reviewed_at      timestamptz,
    version          bigint      NOT NULL CHECK (version >= 1),
    PRIMARY KEY (tenant_id, name),
    CHECK ((status = 'held') = (hold_reason IS NOT NULL))
);

-- Class A: one row per change and per refused attempt, appended in the change's transaction
-- (AC-A2). The database refuses UPDATE, DELETE and TRUNCATE.
CREATE TABLE IF NOT EXISTS tenant_tool_audit (
    id               bigserial   PRIMARY KEY,
    tenant_id        text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    at               timestamptz NOT NULL,
    actor            text        NOT NULL CHECK (actor <> '' AND length(actor) <= 1024),
    cross_tenant     boolean     NOT NULL,
    operator         boolean     NOT NULL,
    action           text        NOT NULL
                     CHECK (action IN ('put', 'delete', 'screen_block', 'approve', 'reject')),
    name             text        NOT NULL CHECK (name ~ '^[a-z0-9_.-]{1,64}$'),
    description_hash text        CHECK (description_hash ~ '^sha256:[0-9a-f]{64}$'),
    status           text        CHECK (status IN ('accepted', 'held', 'rejected')),
    reason           text        CHECK (reason IN ('screening', 'vocabulary')),
    -- (rule key, action) pairs that blocked a refused attempt; never a score.
    fired            jsonb       NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS tenant_tool_audit_by_tenant ON tenant_tool_audit (tenant_id, id);

CREATE OR REPLACE FUNCTION tenant_tool_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tenant_tool_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER tenant_tool_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON tenant_tool_audit
    FOR EACH ROW EXECUTE FUNCTION tenant_tool_audit_immutable();
CREATE OR REPLACE TRIGGER tenant_tool_audit_no_truncate
    BEFORE TRUNCATE ON tenant_tool_audit
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_tool_audit_immutable();

ALTER TABLE tenant_tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_tools FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_tools;
CREATE POLICY tenant_scope ON tenant_tools
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_tool_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_tool_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_tool_audit;
CREATE POLICY tenant_scope ON tenant_tool_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
