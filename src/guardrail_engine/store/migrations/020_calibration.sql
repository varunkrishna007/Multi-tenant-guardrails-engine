-- M4-01 calibration: the tenant's targets, the stored probabilities, the audit trail.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 006 (row-level security) and 010 (it reuses tenant_golden_immutable()). 021 gives the
-- application role its privileges.
--
-- All three tables are tenant-scoped and under forced row-level security, like the golden sets.

-- The tenant's targets: one row per tenant, replaced when the tenant changes them. Every change
-- is also an event in tenant_calibration_audit, written in the same transaction.
CREATE TABLE IF NOT EXISTS tenant_calibration_targets (
    tenant_id        text        PRIMARY KEY CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    block_precision  numeric(4,2) NOT NULL CHECK (block_precision BETWEEN 0.50 AND 1.00),
    escalate_recall  numeric(4,2) NOT NULL CHECK (escalate_recall BETWEEN 0.50 AND 1.00),
    updated_at       timestamptz NOT NULL,
    updated_by       text        NOT NULL CHECK (updated_by <> '' AND length(updated_by) <= 1024)
);

-- What a tenant rule scored an example: the scoring identity (a hash of the guard point's
-- compiled questions and the floor version) and the content's hash select it. Insert-only: a
-- score is a measurement of those questions on that content, and is not edited.
CREATE TABLE IF NOT EXISTS tenant_calibration_scores (
    tenant_id     text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    scoring       text        NOT NULL CHECK (scoring ~ '^sha256:[0-9a-f]{64}$'),
    guard_point   text        NOT NULL
                  CHECK (guard_point IN ('input', 'plan', 'tool_call', 'tool_result', 'output')),
    content_hash  text        NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    scores        jsonb       NOT NULL,
    scored_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, scoring, guard_point, content_hash)
);

-- Why an example has no score under a scoring identity: one row per attempt, so
-- "refused twice" is two rows. ``deterministic`` (a tenant deny pattern or a PII block stops it
-- before the model), ``too_large`` and a second ``refused`` are terminal: the example leaves the
-- rule's pool. ``failed`` (a transient failure) is retried, behind examples tried less often.
-- Insert-only; at most 20 attempts are kept per example.
CREATE TABLE IF NOT EXISTS tenant_calibration_outcomes (
    tenant_id     text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    scoring       text        NOT NULL CHECK (scoring ~ '^sha256:[0-9a-f]{64}$'),
    guard_point   text        NOT NULL
                  CHECK (guard_point IN ('input', 'plan', 'tool_call', 'tool_result', 'output')),
    content_hash  text        NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    attempt       smallint    NOT NULL CHECK (attempt BETWEEN 1 AND 20),
    cause         text        NOT NULL
                  CHECK (cause IN ('deterministic', 'too_large', 'refused', 'failed')),
    at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, scoring, guard_point, content_hash, attempt)
);

-- Append-only: target changes, with the actor. (Threshold decisions are recorded in the draft's
-- own audit event, ``draft.thresholds``, in the transaction of the write: 022.)
CREATE TABLE IF NOT EXISTS tenant_calibration_audit (
    id           bigserial   PRIMARY KEY,
    tenant_id    text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    at           timestamptz NOT NULL,
    actor        text        NOT NULL CHECK (actor <> '' AND length(actor) <= 1024),
    kind         text        NOT NULL CHECK (kind IN ('targets')),
    cross_tenant boolean     NOT NULL,
    operator     boolean     NOT NULL,
    detail       jsonb       NOT NULL
);

CREATE INDEX IF NOT EXISTS tenant_calibration_audit_by_tenant
    ON tenant_calibration_audit (tenant_id, id);

CREATE OR REPLACE TRIGGER tenant_calibration_scores_immutable
    BEFORE UPDATE OR DELETE ON tenant_calibration_scores
    FOR EACH ROW EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_calibration_outcomes_immutable
    BEFORE UPDATE OR DELETE ON tenant_calibration_outcomes
    FOR EACH ROW EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_calibration_outcomes_no_truncate
    BEFORE TRUNCATE ON tenant_calibration_outcomes
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_calibration_audit_immutable
    BEFORE UPDATE OR DELETE ON tenant_calibration_audit
    FOR EACH ROW EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_calibration_scores_no_truncate
    BEFORE TRUNCATE ON tenant_calibration_scores
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_calibration_audit_no_truncate
    BEFORE TRUNCATE ON tenant_calibration_audit
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_golden_immutable();
CREATE OR REPLACE TRIGGER tenant_calibration_targets_no_truncate
    BEFORE TRUNCATE ON tenant_calibration_targets
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_golden_immutable();

ALTER TABLE tenant_calibration_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_calibration_targets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_calibration_targets;
CREATE POLICY tenant_scope ON tenant_calibration_targets
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_calibration_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_calibration_scores FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_calibration_scores;
CREATE POLICY tenant_scope ON tenant_calibration_scores
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_calibration_outcomes ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_calibration_outcomes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_calibration_outcomes;
CREATE POLICY tenant_scope ON tenant_calibration_outcomes
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_calibration_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_calibration_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_calibration_audit;
CREATE POLICY tenant_scope ON tenant_calibration_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
