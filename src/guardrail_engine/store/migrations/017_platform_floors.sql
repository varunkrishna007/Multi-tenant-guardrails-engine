-- M2-09 floor upgrades (R5): the platform's own tables (releases, approvals, the minimum floor,
-- its class A trail) and the re-pin columns on the tenants' publish trail.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role.
-- 018_platform_grants.sql gives the service role its privileges. The platform tables hold no
-- tenant data and have no tenant column, so they are not under row-level security: only the
-- Admin API's platform routes (platform operators, checked by the authorizer) reach them.

ALTER TABLE tenant_publish_audit
    ADD COLUMN IF NOT EXISTS repin_floor integer CHECK (repin_floor >= 1);
ALTER TABLE tenant_publish_audit
    ADD COLUMN IF NOT EXISTS repin_drops jsonb NOT NULL DEFAULT '[]'::jsonb;

-- One row per proposed floor version. ``released_at`` is set when two different operators have
-- approved; ``security_urgent`` is true only if both approvals said so (it shortens the staging
-- window); ``halted`` refuses promotion of the release's re-pins.
CREATE TABLE IF NOT EXISTS platform_floor_releases (
    floor_version   integer     PRIMARY KEY CHECK (floor_version >= 1),
    floor_hash      text        NOT NULL CHECK (floor_hash ~ '^sha256:[0-9a-f]{64}$'),
    evidence        jsonb       NOT NULL,
    proposed_by     text        NOT NULL CHECK (proposed_by <> '' AND length(proposed_by) <= 1024),
    proposed_at     timestamptz NOT NULL,
    released_at     timestamptz,
    security_urgent boolean     NOT NULL DEFAULT false,
    halted          boolean     NOT NULL DEFAULT false
);

-- Approvals are append-only; one per operator per release.
CREATE TABLE IF NOT EXISTS platform_floor_approvals (
    floor_version integer     NOT NULL REFERENCES platform_floor_releases (floor_version),
    operator      text        NOT NULL CHECK (operator <> '' AND length(operator) <= 1024),
    urgent        boolean     NOT NULL,
    at            timestamptz NOT NULL,
    PRIMARY KEY (floor_version, operator)
);

-- The minimum floor version new publishes may extend (R5.5): at most one row.
CREATE TABLE IF NOT EXISTS platform_floor_state (
    id                    boolean     PRIMARY KEY DEFAULT true CHECK (id),
    minimum_floor_version integer     NOT NULL CHECK (minimum_floor_version >= 1),
    set_by                text        NOT NULL,
    at                    timestamptz NOT NULL
);

-- Class A for the platform's own actions (AC-A2).
CREATE TABLE IF NOT EXISTS platform_audit (
    id            bigserial   PRIMARY KEY,
    at            timestamptz NOT NULL,
    actor         text        NOT NULL CHECK (actor <> '' AND length(actor) <= 1024),
    action        text        NOT NULL CHECK (action IN (
                      'release_proposed', 'release_approved', 'released', 'halt', 'resume',
                      'repin', 'promote', 'raise_minimum')),
    floor_version integer     CHECK (floor_version >= 1),
    tenant_id     text        CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    detail        jsonb       NOT NULL DEFAULT '{}'::jsonb
);

CREATE OR REPLACE FUNCTION platform_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER platform_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON platform_audit
    FOR EACH ROW EXECUTE FUNCTION platform_append_only();
CREATE OR REPLACE TRIGGER platform_audit_no_truncate
    BEFORE TRUNCATE ON platform_audit
    FOR EACH STATEMENT EXECUTE FUNCTION platform_append_only();
CREATE OR REPLACE TRIGGER platform_floor_approvals_no_update_or_delete
    BEFORE UPDATE OR DELETE ON platform_floor_approvals
    FOR EACH ROW EXECUTE FUNCTION platform_append_only();
CREATE OR REPLACE TRIGGER platform_floor_approvals_no_truncate
    BEFORE TRUNCATE ON platform_floor_approvals
    FOR EACH STATEMENT EXECUTE FUNCTION platform_append_only();
