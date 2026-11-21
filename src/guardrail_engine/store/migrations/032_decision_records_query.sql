-- M4-07 the audit query: what the tenant-facing read of decision_records needs.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 026. 033_decision_records_retention_policy.sql (variable retention_role) and the operator
-- policy in 014_operator_policies.sql give the other roles their rows.
--
-- 1. Two columns filled from the record when it is written, so a query filters on columns and
--    never opens the JSON text: ``decision`` (allow, escalate, block, forbidden) and
--    ``fired_rules`` (the keys of the rules that escalated or blocked, enforce or shadow).
--    They are copies of what ``record`` says. A row written before this migration has neither
--    (decision NULL, no fired rules), so it is found by time and guard point only.
--    The rule filter does not read ``fired_rules`` (see decision_record_rules below).
-- 2. Row-level security, forced, like every tenant table (006): the service's role sees and
--    writes only the rows of the tenant its transaction's app.tenant_id names. A row with no
--    tenant (a check whose tenant was never verified) can be written by anyone who may insert,
--    and read by nobody but the roles named below. INSERT and SELECT are separate policies, so
--    the service role has no policy for UPDATE or DELETE at all (it has no grant either).
-- 3. The owner of the table runs ``retention_delete_class_b`` (SECURITY DEFINER, 026). FORCE
--    would stop it too, so the owner gets a policy for exactly what that function does:
--    select, lock (FOR UPDATE, which can't change a row) and delete, for every tenant.
-- 4. Indexes for the query: newest first within a tenant, by guard point, and by decision.
-- 5. decision_record_rules: one row per (record, fired rule), written in the same statement as
--    the record, so "records where rule X fired" is an index range scan. An array column and a
--    GIN index can't do this under row-level security: ``@>`` is not leakproof, so the planner
--    may not use an index for it ahead of the policy and reads every row of the tenant
--    (measured: 225 ms to find nothing in 150,000 rows; linear from there). Equality on text is
--    leakproof, so (tenant_id, rule, ts) is used. The rows go with their record: the retention
--    function's DELETE cascades (foreign-key actions are not subject to row-level security).

ALTER TABLE decision_records ADD COLUMN IF NOT EXISTS decision text
    CHECK (decision IS NULL OR decision IN ('allow', 'escalate', 'block', 'forbidden'));
ALTER TABLE decision_records ADD COLUMN IF NOT EXISTS fired_rules text[] NOT NULL DEFAULT '{}';

ALTER TABLE decision_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_read ON decision_records;
CREATE POLICY tenant_read ON decision_records FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_insert ON decision_records;
CREATE POLICY tenant_insert ON decision_records FOR INSERT
    WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true));

DO $policy$
BEGIN
    EXECUTE 'DROP POLICY IF EXISTS definer_select ON decision_records';
    EXECUTE format(
        'CREATE POLICY definer_select ON decision_records FOR SELECT TO %I USING (true)',
        current_user);
    -- SELECT ... FOR UPDATE SKIP LOCKED needs an UPDATE policy to lock a row. It may lock and
    -- never change: WITH CHECK (false), and the table's trigger refuses every UPDATE anyway.
    EXECUTE 'DROP POLICY IF EXISTS definer_lock ON decision_records';
    EXECUTE format(
        'CREATE POLICY definer_lock ON decision_records FOR UPDATE TO %I '
        'USING (true) WITH CHECK (false)',
        current_user);
    EXECUTE 'DROP POLICY IF EXISTS definer_delete ON decision_records';
    EXECUTE format(
        'CREATE POLICY definer_delete ON decision_records FOR DELETE TO %I USING (true)',
        current_user);
END
$policy$;

CREATE INDEX IF NOT EXISTS decision_records_tenant_guard_point
    ON decision_records (tenant_id, guard_point, ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS decision_records_tenant_decision
    ON decision_records (tenant_id, decision, ts DESC, id DESC);

CREATE TABLE IF NOT EXISTS decision_record_rules (
    record_id  bigint      NOT NULL REFERENCES decision_records (id) ON DELETE CASCADE,
    tenant_id  text        NOT NULL,
    rule       text        NOT NULL CHECK (char_length(rule) BETWEEN 1 AND 128),
    ts         timestamptz NOT NULL,
    PRIMARY KEY (record_id, rule)
);

CREATE INDEX IF NOT EXISTS decision_record_rules_tenant_rule
    ON decision_record_rules (tenant_id, rule, ts DESC, record_id DESC);

ALTER TABLE decision_record_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_record_rules FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_read ON decision_record_rules;
CREATE POLICY tenant_read ON decision_record_rules FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_insert ON decision_record_rules;
CREATE POLICY tenant_insert ON decision_record_rules FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE OR REPLACE FUNCTION decision_record_rules_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'decision_record_rules is insert-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER decision_record_rules_no_update
    BEFORE UPDATE ON decision_record_rules
    FOR EACH ROW EXECUTE FUNCTION decision_record_rules_immutable();
CREATE OR REPLACE TRIGGER decision_record_rules_no_truncate
    BEFORE TRUNCATE ON decision_record_rules
    FOR EACH STATEMENT EXECUTE FUNCTION decision_record_rules_immutable();
