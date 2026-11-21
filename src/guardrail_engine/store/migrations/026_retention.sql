-- M4-09 retention engine, classes A and B: the class B decision-record store, the class A
-- deletion-receipt trail, and the one function that may delete decision records.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role.
-- 029_retention_app_grants.sql and 030_retention_role_grants.sql give out privileges.
--
-- decision_records (R3 class B): one row per check, the audit record as JSON text (hashes,
-- probabilities, verdict, latency, tokens; never content). tenant_id is NULL for a check whose
-- tenant was never verified. retain_until is the record's own deletion time, set when it was
-- written from the tenant's retention then in force. The table is insert-only for every
-- ordinary role (no UPDATE or DELETE grant; a trigger also refuses UPDATE and TRUNCATE).
-- Platform-level like delivery_outbox: no row-level security, because the retention job reads
-- across tenants. A tenant-facing read route must add its own policy first.
--
-- retention_receipts (R3 class A): one row per deletion batch, appended by the deletion
-- function in the same transaction as the delete. It holds the tenant, the class, the cutoff,
-- the count and the run id, never content. Append-only: the database refuses UPDATE, DELETE
-- and TRUNCATE, like the other class A trails.

CREATE TABLE IF NOT EXISTS decision_records (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id     text,
    request_id    text        NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 256),
    guard_point   text        NOT NULL CHECK (char_length(guard_point) BETWEEN 1 AND 64),
    ts            timestamptz NOT NULL,
    retain_until  timestamptz NOT NULL,
    record        text        NOT NULL
);

CREATE INDEX IF NOT EXISTS decision_records_tenant_ts ON decision_records (tenant_id, ts, id);

CREATE OR REPLACE FUNCTION decision_records_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'decision_records is insert-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER decision_records_no_update
    BEFORE UPDATE ON decision_records
    FOR EACH ROW EXECUTE FUNCTION decision_records_immutable();
CREATE OR REPLACE TRIGGER decision_records_no_truncate
    BEFORE TRUNCATE ON decision_records
    FOR EACH STATEMENT EXECUTE FUNCTION decision_records_immutable();

CREATE TABLE IF NOT EXISTS retention_receipts (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id           text        NOT NULL CHECK (char_length(run_id) BETWEEN 1 AND 64),
    at               timestamptz NOT NULL,
    tenant_id        text,
    retention_class  text        NOT NULL CHECK (retention_class IN ('A', 'B')),
    cutoff           timestamptz NOT NULL,
    deleted_count    integer     NOT NULL CHECK (deleted_count >= 0),
    batch            integer     NOT NULL CHECK (batch >= 1),
    retention_days   integer     NOT NULL CHECK (retention_days >= 1),
    source           text        NOT NULL
                     CHECK (source IN ('bundle', 'default', 'clamped', 'fallback'))
);

CREATE INDEX IF NOT EXISTS retention_receipts_by_run ON retention_receipts (run_id, id);

CREATE OR REPLACE FUNCTION retention_receipts_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'retention_receipts is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER retention_receipts_no_update_or_delete
    BEFORE UPDATE OR DELETE ON retention_receipts
    FOR EACH ROW EXECUTE FUNCTION retention_receipts_immutable();
CREATE OR REPLACE TRIGGER retention_receipts_no_truncate
    BEFORE TRUNCATE ON retention_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION retention_receipts_immutable();

-- The only way to delete a decision record. SECURITY DEFINER: it runs with the owner's
-- privileges, so the retention role needs no DELETE or INSERT grant of its own, and EXECUTE is
-- revoked from everyone else (029 and 030 grant what each role needs).
--
-- It deletes at most p_limit of one tenant's records that are past BOTH the tenant cutoff
-- (ts < p_cutoff) and their own retain_until (< least(p_now, the database's clock)), skipping
-- rows another run holds (FOR UPDATE SKIP LOCKED), and appends the receipt in the same
-- transaction. Its own bounds limit what a misused or mistaken call can reach:
--   * p_limit is 1..100000;
--   * p_now is no more than five minutes ahead of the database's clock (it comes from the job's
--     injected clock, which makes the job testable; it may be in the past, which only deletes
--     less, and retain_until is compared with the earlier of p_now and the database's clock);
--   * p_retention_days is 90..36500 (90 is the shortest class B term R3 allows) and p_cutoff is
--     exactly p_now minus that many days, so the receipt's figure always agrees with what was
--     deleted;
--   * p_source is 1..16 lowercase letters (the table's CHECK then limits it to the four terms).
-- The receipt's `at` is the database's clock, never a caller value. `source` stays a caller
-- fact (how the term was reached); the function can't check it.
--
-- search_path. A SECURITY DEFINER function must not resolve a relation through the
-- caller's temporary schema, which PostgreSQL searches FIRST for relation names unless pg_temp
-- is listed: a caller with TEMP (every role has it by default) could otherwise create a temp
-- table named retention_receipts and have the receipt written there. So the function pins
-- search_path = pg_catalog, <the schema these tables are in>, pg_temp (pg_temp explicitly
-- last) and also schema-qualifies every table it touches. The schema is the one the tables
-- were just created in (current_schema(), the first schema of the migration session's
-- search_path; public in a normal deployment), so the function is created by a DO block that
-- fills it in. Run the migration with the same search_path every time.
--
-- A receipt is written for batch 1 even when nothing was deleted (proof the run looked), and
-- for later batches only when they deleted something. Every replica or run writes its own
-- batch-1 receipt, so a tenant's receipts for a day are the sum over run_ids.
DO $create$
BEGIN
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION retention_delete_class_b(
    p_run_id         text,
    p_tenant_id      text,
    p_cutoff         timestamptz,
    p_now            timestamptz,
    p_limit          integer,
    p_retention_days integer,
    p_source         text,
    p_batch          integer
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
DECLARE
    n         integer;
    db_now    timestamptz := clock_timestamp();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'retention batch size must be 1..100000'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_now IS NULL OR p_cutoff IS NULL OR p_now > db_now + interval '5 minutes' THEN
        RAISE EXCEPTION 'retention clock is missing or ahead of the database'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_retention_days IS NULL OR p_retention_days < 90 OR p_retention_days > 36500 THEN
        RAISE EXCEPTION 'retention days must be 90..36500'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_source IS NULL OR p_source !~ '^[a-z]{1,16}$' THEN
        RAISE EXCEPTION 'retention source must be 1..16 lowercase letters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_cutoff IS DISTINCT FROM
       p_now - make_interval(secs => (p_retention_days::bigint * 86400)::double precision) THEN
        RAISE EXCEPTION 'retention cutoff is not the clock minus the retention days'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    WITH doomed AS (
        SELECT id FROM %1$I.decision_records
        WHERE ((p_tenant_id IS NULL AND tenant_id IS NULL) OR tenant_id = p_tenant_id)
          AND ts < p_cutoff
          AND retain_until < least(p_now, db_now)
        ORDER BY id
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    ), gone AS (
        DELETE FROM %1$I.decision_records d USING doomed WHERE d.id = doomed.id RETURNING 1
    )
    SELECT count(*) INTO n FROM gone;

    IF n > 0 OR p_batch = 1 THEN
        INSERT INTO %1$I.retention_receipts
            (run_id, at, tenant_id, retention_class, cutoff, deleted_count, batch,
             retention_days, source)
        VALUES (p_run_id, clock_timestamp(), p_tenant_id, 'B', p_cutoff, n, p_batch,
                p_retention_days, p_source);
    END IF;
    RETURN n;
END;
$body$
    $fn$, current_schema());
END
$create$;

REVOKE ALL ON FUNCTION retention_delete_class_b(
    text, text, timestamptz, timestamptz, integer, integer, text, integer) FROM PUBLIC;
