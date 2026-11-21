-- M2-07 version lifecycle: the candidate pointer and the class A trail of publish, promote,
-- abandon, set-percent and rollback.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role.
-- 013_publish_grants.sql gives the service role its privileges. Both tables are under forced
-- row-level security keyed on the per-transaction app.tenant_id (see 006). The active pointer
-- is policy_active_versions (001); versions are policy_bundle_versions (001).

-- At most one candidate per tenant (PF-7): the primary key is the tenant.
CREATE TABLE IF NOT EXISTS tenant_candidates (
    tenant_id       text        NOT NULL PRIMARY KEY CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    version         bigint      NOT NULL,
    mode            text        NOT NULL CHECK (mode IN ('shadow', 'enforce')),
    rollout_percent integer     NOT NULL CHECK (rollout_percent BETWEEN 1 AND 100),
    at              timestamptz NOT NULL,
    actor           text        NOT NULL CHECK (actor <> '' AND length(actor) <= 1024),
    -- A candidate is always a stored version of the same tenant.
    FOREIGN KEY (tenant_id, version) REFERENCES policy_bundle_versions (tenant_id, version)
);

-- Class A: one row per lifecycle action, appended in the action's transaction (AC-A2). The
-- database refuses UPDATE, DELETE and TRUNCATE. ``rules`` is the per-rule snapshot the R1 shadow
-- soak reads (id, the rule's own mode, a fingerprint of its wording and thresholds).
CREATE TABLE IF NOT EXISTS tenant_publish_audit (
    id                  bigserial   PRIMARY KEY,
    tenant_id           text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    at                  timestamptz NOT NULL,
    actor               text        NOT NULL CHECK (actor <> '' AND length(actor) <= 1024),
    cross_tenant        boolean     NOT NULL,
    operator            boolean     NOT NULL,
    action              text        NOT NULL
                        CHECK (action IN ('publish', 'set_percent', 'promote', 'abandon', 'rollback')),
    version             bigint      NOT NULL CHECK (version >= 1),
    from_version        bigint      CHECK (from_version >= 1),
    mode                text        CHECK (mode IN ('shadow', 'enforce')),
    rollout_percent     integer     CHECK (rollout_percent BETWEEN 1 AND 100),
    bundle_hash         text        CHECK (bundle_hash ~ '^sha256:[0-9a-f]{64}$'),
    draft_hash          text        CHECK (draft_hash ~ '^sha256:[0-9a-f]{64}$'),
    diff                jsonb       NOT NULL DEFAULT '[]'::jsonb,
    note                text        NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    rules               jsonb       NOT NULL DEFAULT '[]'::jsonb,
    becomes_active      boolean     NOT NULL DEFAULT false,
    abandoned_candidate bigint      CHECK (abandoned_candidate >= 1)
);

CREATE INDEX IF NOT EXISTS tenant_publish_audit_by_tenant ON tenant_publish_audit (tenant_id, id);

CREATE OR REPLACE FUNCTION tenant_publish_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tenant_publish_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER tenant_publish_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON tenant_publish_audit
    FOR EACH ROW EXECUTE FUNCTION tenant_publish_audit_immutable();
CREATE OR REPLACE TRIGGER tenant_publish_audit_no_truncate
    BEFORE TRUNCATE ON tenant_publish_audit
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_publish_audit_immutable();

-- Tenant isolation in the database itself.
ALTER TABLE tenant_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_candidates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_candidates;
CREATE POLICY tenant_scope ON tenant_candidates
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_publish_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_publish_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_publish_audit;
CREATE POLICY tenant_scope ON tenant_publish_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
