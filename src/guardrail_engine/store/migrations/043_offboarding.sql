-- M5-07 offboarding (R3): a terminated tenant's classes B, C, D and E, its golden sets and its
-- working data are deleted within 30 days; class A is kept; every deletion has a class A receipt
-- and the end has a class A "offboarding complete" receipt with the counts per class.
--
-- Plain SQL, safe to run more than once (every file of apply_schema's MIGRATIONS is applied in full
-- on each start, so a change to a function here, such as M5-03's stored_content branch, takes
-- effect with the next apply; a migration tool that tracked applied files would need such a change
-- as a new migration instead), PostgreSQL 14 or later. Run as the owner role, after
-- 004 (the directory), 010 (golden sets), 020 (calibration), 024 (outbox and usage), 026 (the
-- retention receipts), 028 (shadow counters), 032 (decision records), 034 (escalation items)
-- and 038 (usage row-level security). 044 gives the retention role its privileges.
--
-- What this file does:
--   1. tenants.status gains 'terminating' and 'terminated', and the directory audit's action
--      gains the same two words. A trigger makes the move one-way: a terminating tenant can only
--      become terminated, a terminated one never changes status again, and neither row can be
--      deleted (class A).
--   2. offboarding_receipts: one row per deleted batch of one table (class A, append-only).
--      offboarding_completions: one row per tenant, written once (class A, append-only).
--   3. offboarding_delete_allowed(tenant): the one test the deletion paths share. True only for
--      a tenant whose status is 'terminated' AND for the tenant the running deletion function
--      named (a transaction-local setting only that function sets).
--   4. The immutability triggers of the four append-only content tables (golden sets and
--      examples, calibration scores and outcomes) let a DELETE through exactly when
--      offboarding_delete_allowed says so. UPDATE and TRUNCATE stay refused, and the class A
--      audit tables keep their old triggers unchanged.
--   5. Policies that let the function's owner see, lock and delete the rows of the two tables
--      whose row-level security had only read and insert policies.
--   6. offboarding_delete_batch, offboarding_complete and offboarding_pending, the only way to
--      delete, finish or list. SECURITY DEFINER, owned by the table owner, so the retention role
--      needs no DELETE or INSERT grant on any table.
--   7. Usage_events is billing evidence. offboarding_usage_summaries (class A, append-only)
--      gets, in the SAME statement that deletes the usage rows, one row per calendar month (UTC)
--      and usage class of the rows just deleted: events, answered calls, input tokens and the
--      cost in USD at the price the caller passed (the configured one; it is stored beside the
--      cost). The totals therefore equal the deleted rows by construction.
--   8. After the completion receipt the job re-sweeps once a day for 7 days
--      (offboarding_resweep_pending lists who is due, offboarding_sweep_log records a sweep in
--      offboarding_sweeps, class A, append-only; day 7 is the last, then the tenant is final).
--      A deletion for a tenant that already has a completion writes its receipt (resweep = true)
--      only if it deleted something.
--   9. The outbox delete (and the completion's check) is limited to the kinds 'usage'
--      and 'escalation'. A pending 'alert' that names the tenant is a platform signal and stays.
--
-- The database, not the caller, decides whether a tenant may be offboarded: every call to
-- offboarding_delete_batch and offboarding_complete reads tenants.status itself, under a lock
-- on the tenant's row (FOR SHARE for a batch, FOR UPDATE for the completion), and refuses
-- (SQLSTATE 55000) anything but 'terminated'. Calling the function directly, as the retention
-- role, for an active, suspended or terminating tenant deletes nothing.
--
-- search_path. Like retention_delete_class_b: SET search_path = pg_catalog, <schema>,
-- pg_temp (pg_temp explicitly last), and every table and function is schema-qualified, so a
-- temporary table made by the caller (a fake `tenants` that says "terminated", or a fake
-- `offboarding_receipts`) can't stand in for the real one. <schema> is current_schema(), the
-- schema these tables were just created in; run the migration with the same search_path as the
-- rest.

-- 1. The directory: two new statuses, one way only.
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_status_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_status_check
    CHECK (status IN ('active', 'suspended', 'offboarded', 'terminating', 'terminated'));
ALTER TABLE tenant_directory_audit DROP CONSTRAINT IF EXISTS tenant_directory_audit_action_check;
ALTER TABLE tenant_directory_audit ADD CONSTRAINT tenant_directory_audit_action_check
    CHECK (action IN ('create', 'update', 'set_status', 'terminating', 'terminated'));

CREATE OR REPLACE FUNCTION tenants_termination_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status IN ('terminating', 'terminated') THEN
            RAISE EXCEPTION 'tenants: a terminating or terminated tenant is class A and stays'
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.status = 'terminated' AND NEW.status IS DISTINCT FROM 'terminated' THEN
        RAISE EXCEPTION 'tenants: a terminated tenant can not change status'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.status = 'terminating' AND NEW.status NOT IN ('terminating', 'terminated') THEN
        RAISE EXCEPTION 'tenants: a terminating tenant can only become terminated'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER tenants_termination_one_way
    BEFORE UPDATE OR DELETE ON tenants
    FOR EACH ROW EXECUTE FUNCTION tenants_termination_guard();

-- 2. The class A receipts.
CREATE TABLE IF NOT EXISTS offboarding_receipts (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id         text        NOT NULL CHECK (char_length(run_id) BETWEEN 1 AND 64),
    at             timestamptz NOT NULL,
    tenant_id      text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    table_name     text        NOT NULL CHECK (table_name IN (
                       'decision_record_rules', 'decision_records', 'usage_events',
                       'tenant_shadow_agreement', 'delivery_outbox', 'escalation_items',
                       'escalation_items.content', 'stored_content', 'nightly_redteam_results',
                       'tenant_golden_examples',
                       'tenant_golden_sets', 'tenant_calibration_scores',
                       'tenant_calibration_outcomes', 'tenant_calibration_targets',
                       'tenant_drafts', 'tenant_candidates', 'tenant_tools')),
    data_class     text        NOT NULL CHECK (data_class IN ('B', 'C', 'D', 'E', 'G', 'W')),
    deleted_count  integer     NOT NULL CHECK (deleted_count >= 0),
    batch          integer     NOT NULL CHECK (batch >= 1),
    resweep        boolean     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS offboarding_receipts_by_tenant ON offboarding_receipts (tenant_id, id);
CREATE INDEX IF NOT EXISTS offboarding_receipts_by_run ON offboarding_receipts (run_id, id);

CREATE TABLE IF NOT EXISTS offboarding_completions (
    tenant_id       text        PRIMARY KEY CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    run_id          text        NOT NULL CHECK (char_length(run_id) BETWEEN 1 AND 64),
    at              timestamptz NOT NULL,
    terminating_at  timestamptz NOT NULL,
    terminated_at   timestamptz,
    deadline        timestamptz NOT NULL,
    within_deadline boolean     NOT NULL,
    counts_by_class jsonb       NOT NULL CHECK (jsonb_typeof(counts_by_class) = 'object'),
    counts_by_table jsonb       NOT NULL CHECK (jsonb_typeof(counts_by_table) = 'object')
);

-- The billing evidence of the deleted usage rows. One row per (batch, month, class);
-- sum over the tenant's rows for the totals. Month is the UTC calendar month of occurred_at.
CREATE TABLE IF NOT EXISTS offboarding_usage_summaries (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id                 text        NOT NULL CHECK (char_length(run_id) BETWEEN 1 AND 64),
    at                     timestamptz NOT NULL,
    tenant_id              text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    month                  text        NOT NULL CHECK (month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    usage_class            text        NOT NULL CHECK (usage_class IN (
                               'answered', 'unknown', 'unanswered', 'provider_safety',
                               'model_skipped', 'patterns_dropped')),
    events                 bigint      NOT NULL CHECK (events >= 1),
    answered_calls         bigint      NOT NULL CHECK (answered_calls >= 0),
    input_tokens           bigint      NOT NULL CHECK (input_tokens >= 0),
    price_per_million_usd  numeric     NOT NULL CHECK (price_per_million_usd >= 0),
    cost_usd               numeric     NOT NULL CHECK (cost_usd >= 0)
);

CREATE INDEX IF NOT EXISTS offboarding_usage_summaries_by_tenant
    ON offboarding_usage_summaries (tenant_id, month, usage_class);

-- One row per daily re-sweep after completion (day 1 to 7), written whether or not the
-- sweep found anything, so "swept on day N" can be shown. The deletions it made have their own
-- receipts in offboarding_receipts (resweep = true).
CREATE TABLE IF NOT EXISTS offboarding_sweeps (
    tenant_id      text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    day            integer     NOT NULL CHECK (day BETWEEN 1 AND 7),
    run_id         text        NOT NULL CHECK (char_length(run_id) BETWEEN 1 AND 64),
    at             timestamptz NOT NULL,
    deleted_count  bigint      NOT NULL CHECK (deleted_count >= 0),
    PRIMARY KEY (tenant_id, day)
);

CREATE OR REPLACE FUNCTION offboarding_receipts_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER offboarding_receipts_no_update_or_delete
    BEFORE UPDATE OR DELETE ON offboarding_receipts
    FOR EACH ROW EXECUTE FUNCTION offboarding_receipts_immutable();
CREATE OR REPLACE TRIGGER offboarding_receipts_no_truncate
    BEFORE TRUNCATE ON offboarding_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION offboarding_receipts_immutable();
CREATE OR REPLACE TRIGGER offboarding_completions_no_update_or_delete
    BEFORE UPDATE OR DELETE ON offboarding_completions
    FOR EACH ROW EXECUTE FUNCTION offboarding_receipts_immutable();
CREATE OR REPLACE TRIGGER offboarding_completions_no_truncate
    BEFORE TRUNCATE ON offboarding_completions
    FOR EACH STATEMENT EXECUTE FUNCTION offboarding_receipts_immutable();
CREATE OR REPLACE TRIGGER offboarding_usage_summaries_no_update_or_delete
    BEFORE UPDATE OR DELETE ON offboarding_usage_summaries
    FOR EACH ROW EXECUTE FUNCTION offboarding_receipts_immutable();
CREATE OR REPLACE TRIGGER offboarding_usage_summaries_no_truncate
    BEFORE TRUNCATE ON offboarding_usage_summaries
    FOR EACH STATEMENT EXECUTE FUNCTION offboarding_receipts_immutable();
CREATE OR REPLACE TRIGGER offboarding_sweeps_no_update_or_delete
    BEFORE UPDATE OR DELETE ON offboarding_sweeps
    FOR EACH ROW EXECUTE FUNCTION offboarding_receipts_immutable();
CREATE OR REPLACE TRIGGER offboarding_sweeps_no_truncate
    BEFORE TRUNCATE ON offboarding_sweeps
    FOR EACH STATEMENT EXECUTE FUNCTION offboarding_receipts_immutable();

-- 5. Policies for the two tables whose row-level security (032, 038) had read and insert only:
-- the function's owner may lock and delete the rows of the tenant the function set.
DO $policy$
BEGIN
    EXECUTE 'DROP POLICY IF EXISTS offboarding_lock ON decision_record_rules';
    EXECUTE format(
        'CREATE POLICY offboarding_lock ON decision_record_rules FOR UPDATE TO %I '
        'USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (false)',
        current_user);
    EXECUTE 'DROP POLICY IF EXISTS offboarding_delete ON decision_record_rules';
    EXECUTE format(
        'CREATE POLICY offboarding_delete ON decision_record_rules FOR DELETE TO %I '
        'USING (tenant_id = current_setting(''app.tenant_id'', true))',
        current_user);
    EXECUTE 'DROP POLICY IF EXISTS offboarding_lock ON usage_events';
    EXECUTE format(
        'CREATE POLICY offboarding_lock ON usage_events FOR UPDATE TO %I '
        'USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (false)',
        current_user);
    EXECUTE 'DROP POLICY IF EXISTS offboarding_delete ON usage_events';
    EXECUTE format(
        'CREATE POLICY offboarding_delete ON usage_events FOR DELETE TO %I '
        'USING (tenant_id = current_setting(''app.tenant_id'', true))',
        current_user);
END
$policy$;

-- 3, 4 and 6: the functions. Created by a DO block so the schema can be filled in.
DO $create$
BEGIN
    -- 3. The shared test.
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION offboarding_delete_allowed(p_tenant_id text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, %1$I, pg_temp AS $body$
    SELECT p_tenant_id IS NOT NULL
       AND current_setting('app.offboarding_tenant', true) IS NOT DISTINCT FROM p_tenant_id
       AND EXISTS (SELECT 1 FROM %1$I.tenants t
                   WHERE t.tenant_id = p_tenant_id AND t.status = 'terminated')
$body$
    $fn$, current_schema());

    -- 4. The content tables' trigger: a DELETE passes for a terminated tenant being offboarded.
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION offboarding_deletable_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, %1$I, pg_temp AS $body$
BEGIN
    IF TG_OP = 'DELETE' AND %1$I.offboarding_delete_allowed(OLD.tenant_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '%% is append-only: %% is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$body$
    $fn$, current_schema());

    -- 6a. One bounded batch of one table, with its receipt.
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION offboarding_delete_batch(
    p_run_id    text,
    p_tenant_id text,
    p_table     text,
    p_limit     integer,
    p_batch     integer,
    p_price     numeric DEFAULT 0.10
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
DECLARE
    n           integer := 0;
    c           integer := 0;
    v_status    text;
    v_class     text;
    v_prev      text := current_setting('app.tenant_id', true);
    v_prev_off  text := current_setting('app.offboarding_tenant', true);
    v_resweep   boolean;
BEGIN
    IF p_price IS NULL OR p_price < 0 OR p_price > 1000000 THEN
        RAISE EXCEPTION 'offboarding price must be 0..1000000 USD per million tokens'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'offboarding batch size must be 1..100000'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_batch IS NULL OR p_batch < 1 THEN
        RAISE EXCEPTION 'offboarding batch must be at least 1'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_run_id IS NULL OR char_length(p_run_id) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION 'offboarding run id must be 1..64 characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_tenant_id IS NULL OR p_tenant_id !~ '^t_[0-9a-z]{1,32}$' THEN
        RAISE EXCEPTION 'offboarding needs a tenant id' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_class := CASE p_table
        WHEN 'decision_record_rules' THEN 'B'
        WHEN 'decision_records' THEN 'B'
        WHEN 'usage_events' THEN 'B'
        WHEN 'tenant_shadow_agreement' THEN 'B'
        WHEN 'delivery_outbox' THEN 'B'
        WHEN 'escalation_items' THEN 'D'
        WHEN 'stored_content' THEN 'C'
        WHEN 'nightly_redteam_results' THEN 'B'
        WHEN 'tenant_golden_examples' THEN 'G'
        WHEN 'tenant_golden_sets' THEN 'G'
        WHEN 'tenant_calibration_scores' THEN 'E'
        WHEN 'tenant_calibration_outcomes' THEN 'E'
        WHEN 'tenant_calibration_targets' THEN 'W'
        WHEN 'tenant_drafts' THEN 'W'
        WHEN 'tenant_candidates' THEN 'W'
        WHEN 'tenant_tools' THEN 'W'
    END;
    IF v_class IS NULL THEN
        RAISE EXCEPTION 'that table is not an offboarding table'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- The database decides: the tenant's own row, locked so its status can't move mid-batch.
    SELECT t.status INTO v_status FROM %1$I.tenants t WHERE t.tenant_id = p_tenant_id FOR SHARE;
    IF v_status IS DISTINCT FROM 'terminated' THEN
        RAISE EXCEPTION 'offboarding: the tenant is not terminated'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;

    -- A tenant that already has its completion receipt is being re-swept: its
    -- receipts are written only for a batch that deleted something.
    v_resweep := EXISTS (SELECT 1 FROM %1$I.offboarding_completions o
                          WHERE o.tenant_id = p_tenant_id);

    PERFORM set_config('app.tenant_id', p_tenant_id, true);
    PERFORM set_config('app.offboarding_tenant', p_tenant_id, true);

    IF p_table = 'decision_record_rules' THEN
        WITH gone AS (
            DELETE FROM %1$I.decision_record_rules WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.decision_record_rules WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'decision_records' THEN
        WITH gone AS (
            DELETE FROM %1$I.decision_records WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.decision_records WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'usage_events' THEN
        -- The billing summary of exactly the rows this statement deletes, written by
        -- the same statement (so in the same transaction, and never for a row left behind).
        WITH gone AS (
            DELETE FROM %1$I.usage_events WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.usage_events WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED))
            RETURNING kind, input_tokens, occurred_at),
        summed AS (
            INSERT INTO %1$I.offboarding_usage_summaries
                (run_id, at, tenant_id, month, usage_class, events, answered_calls,
                 input_tokens, price_per_million_usd, cost_usd)
            SELECT p_run_id, clock_timestamp(), p_tenant_id,
                   to_char(g.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM'), g.kind,
                   count(*), count(*) FILTER (WHERE g.kind = 'answered'),
                   coalesce(sum(g.input_tokens), 0)::bigint, p_price,
                   coalesce(sum(g.input_tokens), 0)::numeric * p_price / 1000000
              FROM gone g
             GROUP BY to_char(g.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM'), g.kind
            RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_shadow_agreement' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_shadow_agreement WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_shadow_agreement WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'delivery_outbox' THEN
        -- The outbox has no tenant column; every payload is compact JSON with "tenant_id".
        -- position(), not LIKE: a tenant id holds underscores, which LIKE reads as wildcards.
        -- Only the tenant's own kinds (usage, escalation). A pending 'alert' that names
        -- the tenant is a platform signal (an ops page about it) and stays until delivered.
        WITH gone AS (
            DELETE FROM %1$I.delivery_outbox WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.delivery_outbox
                WHERE kind IN ('usage', 'escalation')
                  AND position('"tenant_id":"' || p_tenant_id || '"' IN payload) > 0
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'escalation_items' THEN
        WITH gone AS (
            DELETE FROM %1$I.escalation_items WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.escalation_items WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED))
            RETURNING (content IS NOT NULL AND store_content = 'full') AS held)
        SELECT count(*)::integer, (count(*) FILTER (WHERE held))::integer INTO n, c FROM gone;
    ELSIF p_table = 'stored_content' THEN  -- M5-03, class C
        WITH gone AS (
            DELETE FROM %1$I.stored_content WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.stored_content WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'nightly_redteam_results' THEN  -- M5-05, class B
        WITH gone AS (
            DELETE FROM %1$I.nightly_redteam_results WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.nightly_redteam_results WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_golden_examples' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_golden_examples WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_golden_examples WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_golden_sets' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_golden_sets WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_golden_sets WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_calibration_scores' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_calibration_scores WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_calibration_scores WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_calibration_outcomes' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_calibration_outcomes WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_calibration_outcomes WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_calibration_targets' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_calibration_targets WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_calibration_targets WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_drafts' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_drafts WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_drafts WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_candidates' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_candidates WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_candidates WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    ELSIF p_table = 'tenant_tools' THEN
        WITH gone AS (
            DELETE FROM %1$I.tenant_tools WHERE ctid = ANY (ARRAY(
                SELECT ctid FROM %1$I.tenant_tools WHERE tenant_id = p_tenant_id
                LIMIT p_limit FOR UPDATE SKIP LOCKED)) RETURNING 1)
        SELECT count(*)::integer INTO n FROM gone;
    END IF;

    -- The receipts, in the same transaction as the delete: a receipt for batch 1 even when
    -- nothing was deleted (proof the run looked), for a later batch only if it deleted; and for
    -- a re-sweep only if it deleted.
    IF n > 0 OR (p_batch = 1 AND NOT v_resweep) THEN
        INSERT INTO %1$I.offboarding_receipts
            (run_id, at, tenant_id, table_name, data_class, deleted_count, batch, resweep)
        VALUES (p_run_id, clock_timestamp(), p_tenant_id, p_table, v_class, n, p_batch,
                v_resweep);
        IF p_table = 'escalation_items' THEN
            INSERT INTO %1$I.offboarding_receipts
                (run_id, at, tenant_id, table_name, data_class, deleted_count, batch, resweep)
            VALUES (p_run_id, clock_timestamp(), p_tenant_id, 'escalation_items.content', 'C',
                    c, p_batch, v_resweep);
        END IF;
    END IF;

    PERFORM set_config('app.tenant_id', coalesce(v_prev, ''), true);
    PERFORM set_config('app.offboarding_tenant', coalesce(v_prev_off, ''), true);
    RETURN n;
END;
$body$
    $fn$, current_schema());

    -- 6b. Finish: verify nothing is left, then write the one completion receipt.
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION offboarding_complete(
    p_run_id    text,
    p_tenant_id text,
    p_now       timestamptz
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
DECLARE
    db_now      timestamptz := clock_timestamp();
    v_status    text;
    v_updated   timestamptz;
    v_term      timestamptz;
    v_done      timestamptz;
    v_by_class  jsonb;
    v_by_table  jsonb;
    v_left      boolean;
    v_rows      integer;
    v_prev      text := current_setting('app.tenant_id', true);
BEGIN
    IF p_now IS NULL OR p_now > db_now + interval '5 minutes' THEN
        RAISE EXCEPTION 'offboarding clock is missing or ahead of the database'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_run_id IS NULL OR char_length(p_run_id) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION 'offboarding run id must be 1..64 characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_tenant_id IS NULL OR p_tenant_id !~ '^t_[0-9a-z]{1,32}$' THEN
        RAISE EXCEPTION 'offboarding needs a tenant id' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- FOR UPDATE: one completer at a time (and no batch runs while this one counts).
    SELECT t.status, t.updated_at INTO v_status, v_updated
      FROM %1$I.tenants t WHERE t.tenant_id = p_tenant_id FOR UPDATE;
    IF v_status IS DISTINCT FROM 'terminated' THEN
        RAISE EXCEPTION 'offboarding: the tenant is not terminated'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    IF EXISTS (SELECT 1 FROM %1$I.offboarding_completions o WHERE o.tenant_id = p_tenant_id) THEN
        RETURN 'already_complete';
    END IF;

    PERFORM set_config('app.tenant_id', p_tenant_id, true);
    v_left :=
        EXISTS (SELECT 1 FROM %1$I.decision_record_rules WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.decision_records WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.usage_events WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_shadow_agreement WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.delivery_outbox
                WHERE kind IN ('usage', 'escalation')
                  AND position('"tenant_id":"' || p_tenant_id || '"' IN payload) > 0)
     OR EXISTS (SELECT 1 FROM %1$I.escalation_items WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.stored_content WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.nightly_redteam_results WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_golden_examples WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_golden_sets WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_calibration_scores WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_calibration_outcomes WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_calibration_targets WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_drafts WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_candidates WHERE tenant_id = p_tenant_id)
     OR EXISTS (SELECT 1 FROM %1$I.tenant_tools WHERE tenant_id = p_tenant_id);
    PERFORM set_config('app.tenant_id', coalesce(v_prev, ''), true);
    IF v_left THEN
        RETURN 'remaining';
    END IF;

    SELECT min(a.at) FILTER (WHERE a.action = 'terminating'),
           min(a.at) FILTER (WHERE a.action = 'terminated')
      INTO v_term, v_done
      FROM %1$I.tenant_directory_audit a WHERE a.tenant_id = p_tenant_id;
    v_term := coalesce(v_term, v_updated);

    SELECT jsonb_object_agg(k.c, coalesce(s.n, 0))
      INTO v_by_class
      FROM unnest(ARRAY['B', 'C', 'D', 'E', 'G', 'W']) AS k(c)
      LEFT JOIN (SELECT r.data_class, sum(r.deleted_count)::bigint AS n
                   FROM %1$I.offboarding_receipts r WHERE r.tenant_id = p_tenant_id
                  GROUP BY r.data_class) s ON s.data_class = k.c;
    SELECT coalesce(jsonb_object_agg(s.table_name, s.n), '{}'::jsonb)
      INTO v_by_table
      FROM (SELECT r.table_name, sum(r.deleted_count)::bigint AS n
              FROM %1$I.offboarding_receipts r WHERE r.tenant_id = p_tenant_id
             GROUP BY r.table_name) s;

    INSERT INTO %1$I.offboarding_completions
        (tenant_id, run_id, at, terminating_at, terminated_at, deadline, within_deadline,
         counts_by_class, counts_by_table)
    VALUES (p_tenant_id, p_run_id, clock_timestamp(), v_term, v_done,
            v_term + interval '30 days', p_now <= v_term + interval '30 days',
            v_by_class, v_by_table)
    ON CONFLICT (tenant_id) DO NOTHING;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN CASE WHEN v_rows = 1 THEN 'completed' ELSE 'already_complete' END;
END;
$body$
    $fn$, current_schema());

    -- 6c. Who is waiting.
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION offboarding_pending(p_limit integer)
RETURNS TABLE (r_tenant_id text, r_status text, r_terminating_at timestamptz,
               r_terminated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'offboarding list size must be 1..100000'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN QUERY
    SELECT t.tenant_id, t.status, coalesce(a.terminating, t.updated_at), a.terminated
      FROM %1$I.tenants t
      LEFT JOIN LATERAL (
          SELECT min(d.at) FILTER (WHERE d.action = 'terminating') AS terminating,
                 min(d.at) FILTER (WHERE d.action = 'terminated') AS terminated
            FROM %1$I.tenant_directory_audit d WHERE d.tenant_id = t.tenant_id) a ON true
     WHERE t.status IN ('terminating', 'terminated')
       AND NOT EXISTS (SELECT 1 FROM %1$I.offboarding_completions o
                        WHERE o.tenant_id = t.tenant_id)
     ORDER BY coalesce(a.terminating, t.updated_at), t.tenant_id
     LIMIT p_limit;
END;
$body$
    $fn$, current_schema());

    -- 8a. Who is due a daily re-sweep. Day N is due N days after the completion receipt;
    -- the day reported is the latest one due (capped at 7), so a job that was down catches up
    -- with one sweep. A tenant whose day-7 sweep is logged is final and is never listed.
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION offboarding_resweep_pending(p_now timestamptz, p_limit integer)
RETURNS TABLE (r_tenant_id text, r_day integer, r_completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
BEGIN
    -- Read-only, so the caller's clock isn't bounded here (offboarding_sweep_log, which writes,
    -- bounds it: a clock ahead of the database can list a day early but never log it early).
    IF p_now IS NULL THEN
        RAISE EXCEPTION 'offboarding clock is missing' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'offboarding list size must be 1..100000'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN QUERY
    SELECT o.tenant_id, d.day, o.at
      FROM %1$I.offboarding_completions o
      JOIN %1$I.tenants t ON t.tenant_id = o.tenant_id AND t.status = 'terminated'
      CROSS JOIN LATERAL (
          SELECT least(7, floor(extract(epoch FROM (p_now - o.at)) / 86400))::integer AS day
      ) d
     WHERE d.day >= 1
       AND d.day > coalesce((SELECT max(s.day) FROM %1$I.offboarding_sweeps s
                              WHERE s.tenant_id = o.tenant_id), 0)
     ORDER BY o.at, o.tenant_id
     LIMIT p_limit;
END;
$body$
    $fn$, current_schema());

    -- 8b. Record that the day's sweep ran (whether or not it deleted anything). The day can't
    -- be ahead of what the clock allows, and the tenant must have its completion receipt.
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION offboarding_sweep_log(
    p_run_id    text,
    p_tenant_id text,
    p_day       integer,
    p_deleted   bigint,
    p_now       timestamptz
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
DECLARE
    v_done  timestamptz;
    v_rows  integer;
BEGIN
    IF p_now IS NULL OR p_now > clock_timestamp() + interval '5 minutes' THEN
        RAISE EXCEPTION 'offboarding clock is missing or ahead of the database'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_run_id IS NULL OR char_length(p_run_id) NOT BETWEEN 1 AND 64
       OR p_tenant_id IS NULL OR p_tenant_id !~ '^t_[0-9a-z]{1,32}$'
       OR p_day IS NULL OR p_day NOT BETWEEN 1 AND 7
       OR p_deleted IS NULL OR p_deleted < 0 THEN
        RAISE EXCEPTION 'offboarding sweep log: bad arguments'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT o.at INTO v_done FROM %1$I.offboarding_completions o WHERE o.tenant_id = p_tenant_id;
    IF v_done IS NULL OR p_now < v_done + (p_day * interval '1 day') THEN
        RAISE EXCEPTION 'offboarding sweep log: that day is not due'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    INSERT INTO %1$I.offboarding_sweeps (tenant_id, day, run_id, at, deleted_count)
    VALUES (p_tenant_id, p_day, p_run_id, clock_timestamp(), p_deleted)
    ON CONFLICT (tenant_id, day) DO NOTHING;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows = 1;
END;
$body$
    $fn$, current_schema());
END
$create$;

REVOKE ALL ON FUNCTION offboarding_delete_allowed(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION offboarding_delete_batch(text, text, text, integer, integer, numeric)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION offboarding_complete(text, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION offboarding_pending(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION offboarding_resweep_pending(timestamptz, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION offboarding_sweep_log(text, text, integer, bigint, timestamptz)
    FROM PUBLIC;

-- 4. The four content tables let offboarding_delete_allowed's DELETE through. (Last, after the
-- function exists. 010 and 020 created these triggers with the strict function; the class A
-- audit tables keep it.)
CREATE OR REPLACE TRIGGER tenant_golden_sets_immutable
    BEFORE UPDATE OR DELETE ON tenant_golden_sets
    FOR EACH ROW EXECUTE FUNCTION offboarding_deletable_guard();
CREATE OR REPLACE TRIGGER tenant_golden_examples_immutable
    BEFORE UPDATE OR DELETE ON tenant_golden_examples
    FOR EACH ROW EXECUTE FUNCTION offboarding_deletable_guard();
CREATE OR REPLACE TRIGGER tenant_calibration_scores_immutable
    BEFORE UPDATE OR DELETE ON tenant_calibration_scores
    FOR EACH ROW EXECUTE FUNCTION offboarding_deletable_guard();
CREATE OR REPLACE TRIGGER tenant_calibration_outcomes_immutable
    BEFORE UPDATE OR DELETE ON tenant_calibration_outcomes
    FOR EACH ROW EXECUTE FUNCTION offboarding_deletable_guard();
