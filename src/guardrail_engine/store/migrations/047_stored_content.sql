-- M5-03 stored content (R3 class C): the post-redaction text of the content a check evaluated,
-- kept only for a tenant that turned it on (``audit.store_content: full``), for at most the R3
-- cap, and the class C deletion function.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after 006
-- (row-level security) and 026/034 (the retention receipts it widens). 048 to 050 give out
-- privileges.
--
-- stored_content: one row per stored check. Tenant-scoped under **forced** row-level security
-- (the tenant setting ``app.tenant_id``). **Insert-only**: the application role has SELECT and
-- INSERT only; a trigger refuses UPDATE and TRUNCATE for everyone; the only deletion paths are
-- retention_delete_class_c (below) and the terminated-tenant offboarding function (043).
-- ``content`` is post-redaction text (PII replaced by the engine's placeholders before the model
-- saw it); ``content_sha256`` is the hash of the **pre-redaction** content (PF-14), kept so a
-- row can be matched to its decision record without reading the content. ``retain_until`` is
-- the row's own deletion time, set when it was written from the tenant's term clamped to the R3
-- cap then in force (90 days at most; 30 for a tenant whose packs need a BAA). The CHECK below
-- is the last line: no row can be written to live longer than 90 days, whatever wrote it.

CREATE TABLE IF NOT EXISTS stored_content (
    seq            bigint      GENERATED ALWAYS AS IDENTITY,
    tenant_id      text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    request_id     text        NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 256),
    guard_point    text        NOT NULL
                   CHECK (guard_point IN ('input', 'plan', 'tool_call', 'tool_result', 'output')),
    ts             timestamptz NOT NULL,
    retain_until   timestamptz NOT NULL,
    content        text        NOT NULL CHECK (char_length(content) <= 100000),
    truncated      boolean     NOT NULL DEFAULT false,
    content_sha256 text        NOT NULL CHECK (content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    bundle_version bigint      CHECK (bundle_version IS NULL OR bundle_version >= 1),
    PRIMARY KEY (tenant_id, seq),
    CHECK (retain_until > ts AND retain_until <= ts + interval '90 days')
);

CREATE INDEX IF NOT EXISTS stored_content_by_request
    ON stored_content (tenant_id, request_id, guard_point);
CREATE INDEX IF NOT EXISTS stored_content_by_expiry ON stored_content (tenant_id, retain_until);

CREATE OR REPLACE FUNCTION stored_content_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'stored_content is insert-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER stored_content_no_update
    BEFORE UPDATE ON stored_content
    FOR EACH ROW EXECUTE FUNCTION stored_content_immutable();
CREATE OR REPLACE TRIGGER stored_content_no_truncate
    BEFORE TRUNCATE ON stored_content
    FOR EACH STATEMENT EXECUTE FUNCTION stored_content_immutable();

ALTER TABLE stored_content ENABLE ROW LEVEL SECURITY;
ALTER TABLE stored_content FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON stored_content;
CREATE POLICY tenant_scope ON stored_content
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- stored_content_audit (R3 class A): one row per read of stored content through the Admin API: who
-- (``issuer#subject``), which request and guard point they asked for, how many rows they got
-- (0 for a request that found nothing: someone asked), whether the read crossed tenants and
-- whether the actor is a platform operator. **Never the content.** Append-only: the database
-- refuses UPDATE, DELETE and TRUNCATE, like the other class A trails; kept at offboarding.
CREATE TABLE IF NOT EXISTS stored_content_audit (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id    text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    at           timestamptz NOT NULL,
    actor        text        NOT NULL CHECK (actor <> '' AND char_length(actor) <= 1024),
    request_id   text        NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 256),
    guard_point  text        CHECK (guard_point IS NULL OR guard_point IN
                                    ('input', 'plan', 'tool_call', 'tool_result', 'output')),
    items        integer     NOT NULL CHECK (items >= 0),
    cross_tenant boolean     NOT NULL,
    operator     boolean     NOT NULL
);

CREATE INDEX IF NOT EXISTS stored_content_audit_by_tenant ON stored_content_audit (tenant_id, id);

CREATE OR REPLACE FUNCTION stored_content_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'stored_content_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER stored_content_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON stored_content_audit
    FOR EACH ROW EXECUTE FUNCTION stored_content_audit_immutable();
CREATE OR REPLACE TRIGGER stored_content_audit_no_truncate
    BEFORE TRUNCATE ON stored_content_audit
    FOR EACH STATEMENT EXECUTE FUNCTION stored_content_audit_immutable();

ALTER TABLE stored_content_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE stored_content_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON stored_content_audit;
CREATE POLICY tenant_scope ON stored_content_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- The class A receipts (026, 034) also record class C deletions. A class C row carries its own
-- deletion time, so a receipt's ``source`` is 'row' and its ``retention_days`` is the R3 cap the
-- function enforced (90).
ALTER TABLE retention_receipts DROP CONSTRAINT IF EXISTS retention_receipts_retention_class_check;
ALTER TABLE retention_receipts ADD CONSTRAINT retention_receipts_retention_class_check
    CHECK (retention_class IN ('A', 'B', 'C', 'D'));
ALTER TABLE retention_receipts DROP CONSTRAINT IF EXISTS retention_receipts_source_check;
ALTER TABLE retention_receipts ADD CONSTRAINT retention_receipts_source_check
    CHECK (source IN ('bundle', 'default', 'clamped', 'fallback', 'healthcare', 'row'));

-- The only way the retention job deletes stored content (R3 class C). SECURITY DEFINER with a
-- pinned search_path and schema-qualified tables, exactly as retention_delete_class_b (026) and
-- retention_delete_class_d (034), so the retention role needs no DELETE or INSERT grant.
--
-- **The database, not the caller, decides what is due.** A row goes when its own retain_until is
-- before the cutoff, or, as a ceiling that no bad retain_until can outlive, when it was stored
-- more than 90 days before it. The cutoff is the caller's p_now clamped to the database's own
-- clock (p_now more than five minutes ahead of it is refused), so a mistaken or hostile clock
-- can only delete less. Both comparisons are strict: a row exactly at the cutoff is kept.
-- p_limit 1..100000. A receipt (class C) is written in the same transaction for batch 1 even if
-- nothing was deleted, and for later batches only if they deleted something. Rows another run
-- holds are skipped (FOR UPDATE SKIP LOCKED). The transaction-local tenant setting is put back
-- as it was.
DO $create$
BEGIN
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION retention_delete_class_c(
    p_run_id    text,
    p_tenant_id text,
    p_now       timestamptz,
    p_limit     integer,
    p_batch     integer
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
DECLARE
    n         integer;
    db_now    timestamptz := clock_timestamp();
    v_cutoff  timestamptz;
    v_prev    text := current_setting('app.tenant_id', true);
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'class C batch size must be 1..100000'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_now IS NULL OR p_now > db_now + interval '5 minutes' THEN
        RAISE EXCEPTION 'class C clock is missing or ahead of the database'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_batch IS NULL OR p_batch < 1 THEN
        RAISE EXCEPTION 'class C batch must be at least 1'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_run_id IS NULL OR char_length(p_run_id) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION 'class C run id must be 1..64 characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_tenant_id IS NULL OR p_tenant_id !~ '^t_[0-9a-z]{1,32}$' THEN
        RAISE EXCEPTION 'class C needs a tenant id' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_cutoff := least(p_now, db_now);
    PERFORM set_config('app.tenant_id', p_tenant_id, true);

    WITH doomed AS (
        SELECT c.tenant_id, c.seq FROM %1$I.stored_content c
        WHERE c.tenant_id = p_tenant_id
          AND (c.retain_until < v_cutoff OR c.ts < v_cutoff - interval '90 days')
        ORDER BY c.seq
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    ), gone AS (
        DELETE FROM %1$I.stored_content d USING doomed
        WHERE d.tenant_id = doomed.tenant_id AND d.seq = doomed.seq
        RETURNING 1
    )
    SELECT count(*)::integer INTO n FROM gone;

    IF n > 0 OR p_batch = 1 THEN
        INSERT INTO %1$I.retention_receipts
            (run_id, at, tenant_id, retention_class, cutoff, deleted_count, batch,
             retention_days, source)
        VALUES (p_run_id, clock_timestamp(), p_tenant_id, 'C', v_cutoff, n, p_batch, 90, 'row');
    END IF;
    PERFORM set_config('app.tenant_id', coalesce(v_prev, ''), true);
    RETURN n;
END;
$body$
    $fn$, current_schema());
END
$create$;

REVOKE ALL ON FUNCTION retention_delete_class_c(text, text, timestamptz, integer, integer)
    FROM PUBLIC;
