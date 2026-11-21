-- M5-05 nightly red-team: the result of the M2-08 suite for a tenant's active version.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after 006
-- (row-level security). 052 and 053 give out privileges.
--
-- nightly_redteam_results: one row per (tenant, bundle version, night). The suite is run once per
-- distinct configuration (the Gemini project the tenant is served from, the floor version and the
-- packs a bundle extends; M5-06: a regulated tenant's dedicated project is its own) on a synthetic tenant,
-- and the outcome is recorded for every tenant version that has that configuration, so a
-- result is the platform layers' recall, never a tenant's own rules. It holds the status, the
-- per-rule block_at recall counts, the regressions found (rule keys and counts), and what the run
-- cost. **No content**: no corpus row, no payload, no provider text. Tenant-scoped under forced
-- row-level security; **insert-only** for the application and operator roles (SELECT and INSERT, no
-- UPDATE or DELETE; a trigger refuses UPDATE and TRUNCATE for everyone). The only deletion is a
-- terminated tenant's offboarding function (043): class B, derived metrics about its versions.

CREATE TABLE IF NOT EXISTS nightly_redteam_results (
    id                   bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id            text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    bundle_version       bigint      NOT NULL CHECK (bundle_version >= 1),
    project              text        NOT NULL DEFAULT ''
                         CHECK (project = '' OR project ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
    nonce_seed           text        NOT NULL DEFAULT ''
                         CHECK (nonce_seed = '' OR nonce_seed ~ '^[0-9a-f]{32}$'),
    config_key           text        NOT NULL CHECK (char_length(config_key) BETWEEN 1 AND 1024),
    run_id               text        NOT NULL CHECK (char_length(run_id) BETWEEN 1 AND 64),
    run_at               timestamptz NOT NULL,
    mode                 text        NOT NULL CHECK (mode IN ('fake', 'live')),
    floor_version        integer     NOT NULL CHECK (floor_version >= 1),
    packs                text[]      NOT NULL DEFAULT '{}',
    corpus_sha256        text        NOT NULL CHECK (corpus_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    draws                integer     NOT NULL CHECK (draws >= 1),
    rows                 integer     NOT NULL CHECK (rows >= 0),
    status               text        NOT NULL
                         CHECK (status IN ('pass', 'regression', 'refused', 'stopped')),
    regressions          jsonb       NOT NULL DEFAULT '[]'::jsonb
                         CHECK (jsonb_typeof(regressions) = 'array'
                                AND jsonb_array_length(regressions) <= 50),
    block_recall         jsonb       NOT NULL DEFAULT '{}'::jsonb
                         CHECK (jsonb_typeof(block_recall) = 'object'),
    false_act            jsonb       NOT NULL DEFAULT '{}'::jsonb
                         CHECK (jsonb_typeof(false_act) = 'object'),
    structure_violations integer     NOT NULL DEFAULT 0 CHECK (structure_violations >= 0),
    provider_calls       integer     NOT NULL DEFAULT 0 CHECK (provider_calls >= 0),
    input_tokens         bigint      NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    note                 text        NOT NULL DEFAULT '' CHECK (char_length(note) <= 200),
    UNIQUE (tenant_id, bundle_version, run_id)
);

CREATE INDEX IF NOT EXISTS nightly_redteam_by_tenant
    ON nightly_redteam_results (tenant_id, run_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS nightly_redteam_by_config
    ON nightly_redteam_results (config_key, mode, run_at DESC);
CREATE INDEX IF NOT EXISTS nightly_redteam_by_project
    ON nightly_redteam_results (project, run_at DESC);

CREATE OR REPLACE FUNCTION nightly_redteam_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'nightly_redteam_results is insert-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER nightly_redteam_no_update
    BEFORE UPDATE ON nightly_redteam_results
    FOR EACH ROW EXECUTE FUNCTION nightly_redteam_immutable();
CREATE OR REPLACE TRIGGER nightly_redteam_no_truncate
    BEFORE TRUNCATE ON nightly_redteam_results
    FOR EACH STATEMENT EXECUTE FUNCTION nightly_redteam_immutable();

ALTER TABLE nightly_redteam_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE nightly_redteam_results FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON nightly_redteam_results;
CREATE POLICY tenant_scope ON nightly_redteam_results
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- nightly_redteam_quarantine (class A): a configuration whose run hit a provider refusal
-- is quarantined (a ``quarantine`` event, actor ``nightly``) and is never sent again until a
-- platform operator clears it (a ``clear`` event with the operator's actor and reason). The table
-- is the trail and the state at once: a configuration is quarantined while its latest event is a
-- ``quarantine``. Platform data (no tenant column, no row-level security: it names a configuration
-- and a project, never a tenant, a row or provider text). Append-only: the database refuses UPDATE,
-- DELETE and TRUNCATE.
CREATE TABLE IF NOT EXISTS nightly_redteam_quarantine (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    config_key text        NOT NULL CHECK (char_length(config_key) BETWEEN 1 AND 1024),
    mode       text        NOT NULL CHECK (mode IN ('fake', 'live')),
    project    text        NOT NULL DEFAULT ''
               CHECK (project = '' OR project ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
    action     text        NOT NULL CHECK (action IN ('quarantine', 'clear')),
    at         timestamptz NOT NULL,
    actor      text        NOT NULL CHECK (actor <> '' AND char_length(actor) <= 1024),
    operator   boolean     NOT NULL,
    reason     text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 200),
    run_id     text        NOT NULL DEFAULT '' CHECK (char_length(run_id) <= 64),
    -- The corpus row the provider refused (an id, never content). A hold on the row
    -- itself has config_key 'row:<id>' and holds it across every configuration and project.
    row_id     text        NOT NULL DEFAULT ''
               CHECK (row_id = '' OR row_id ~ '^[A-Za-z0-9_.:-]{1,80}$')
);

CREATE INDEX IF NOT EXISTS nightly_redteam_quarantine_by_config
    ON nightly_redteam_quarantine (config_key, mode, id);

CREATE OR REPLACE FUNCTION nightly_redteam_quarantine_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'nightly_redteam_quarantine is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER nightly_redteam_quarantine_no_update_or_delete
    BEFORE UPDATE OR DELETE ON nightly_redteam_quarantine
    FOR EACH ROW EXECUTE FUNCTION nightly_redteam_quarantine_immutable();
CREATE OR REPLACE TRIGGER nightly_redteam_quarantine_no_truncate
    BEFORE TRUNCATE ON nightly_redteam_quarantine
    FOR EACH STATEMENT EXECUTE FUNCTION nightly_redteam_quarantine_immutable();
