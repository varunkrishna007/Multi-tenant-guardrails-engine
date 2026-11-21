-- M4-05 escalation queue: the items held for a reviewer (R3 class D), the class A trail of their
-- resolutions, the outbox kind for escalation webhooks and the class D deletion function.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after 006
-- (row-level security) and 024/026 (the outbox and the retention receipts it widens).
-- 035 to 037 give out privileges.
--
-- escalation_items (R3 class D): one row per escalate verdict the router stored. It holds the
-- rules that fired (key, action, mode, layer: never a probability), the hash of the pre-redaction
-- content and, only where R3 allows, the post-redaction text held for the reviewer. Tenant-scoped
-- under forced row-level security. **Insert-only except for the resolution**: the application
-- role has no DELETE, only a column-level UPDATE on the resolution and label columns, and the
-- trigger below allows exactly two updates, open -> resolved (resolution columns, once) and
-- attaching the label to a resolved row (once), leaving every other column as it was. The only
-- way to delete an item is retention_delete_class_d.
--
-- escalation_audit (R3 class A): who resolved which item and made which label. Append-only.
-- The reviewer's free-text reason is stored as a hash only, never as text.

CREATE TABLE IF NOT EXISTS escalation_items (
    seq               bigint      GENERATED ALWAYS AS IDENTITY,
    tenant_id         text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    id                text        NOT NULL CHECK (id ~ '^esc_[0-9a-f]{24}$'),
    request_id        text        NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 256),
    guard_point       text        NOT NULL
                      CHECK (guard_point IN ('input', 'plan', 'tool_call', 'tool_result', 'output')),
    created_at        timestamptz NOT NULL,
    target            text        NOT NULL CHECK (target IN ('queue', 'webhook')),
    reason            text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 64),
    bundle_version    bigint      CHECK (bundle_version IS NULL OR bundle_version >= 1),
    rules             jsonb       NOT NULL DEFAULT '[]'::jsonb,
    content_sha256    text        CHECK (content_sha256 IS NULL
                                         OR content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    store_content     text        NOT NULL CHECK (store_content IN ('hash_only', 'full')),
    retention_mode    text        NOT NULL DEFAULT 'resolved_plus'
                      CHECK (retention_mode IN ('resolved_plus', 'total')),
    content           text        CHECK (content IS NULL OR char_length(content) <= 100000),
    content_truncated boolean     NOT NULL DEFAULT false,
    triggered_by      text        CHECK (triggered_by IS NULL OR char_length(triggered_by) <= 1024),
    status            text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    decision          text        CHECK (decision IN ('allow', 'block')),
    resolution_reason text        CHECK (char_length(resolution_reason) BETWEEN 1 AND 500),
    resolved_by       text        CHECK (char_length(resolved_by) BETWEEN 1 AND 1024),
    resolved_at       timestamptz,
    label_set_id      text        CHECK (label_set_id ~ '^gs_[0-9a-f]{16}$'),
    label_mode        text        CHECK (label_mode IN ('content', 'hash_only')),
    PRIMARY KEY (tenant_id, id),
    CHECK (jsonb_typeof(rules) = 'array'),
    CHECK ((status = 'open'
            AND decision IS NULL AND resolution_reason IS NULL
            AND resolved_by IS NULL AND resolved_at IS NULL)
        OR (status = 'resolved'
            AND decision IS NOT NULL AND resolution_reason IS NOT NULL
            AND resolved_by IS NOT NULL AND resolved_at IS NOT NULL)),
    CHECK ((label_set_id IS NULL) = (label_mode IS NULL)),
    CHECK (label_set_id IS NULL OR status = 'resolved')
);

-- The class D term's mode is fixed on the item when it is routed (like store_content),
-- so the deletion function applies the item's own mode and not the caller's.
ALTER TABLE escalation_items
    ADD COLUMN IF NOT EXISTS retention_mode text NOT NULL DEFAULT 'resolved_plus';
ALTER TABLE escalation_items DROP CONSTRAINT IF EXISTS escalation_items_retention_mode_check;
ALTER TABLE escalation_items ADD CONSTRAINT escalation_items_retention_mode_check
    CHECK (retention_mode IN ('resolved_plus', 'total'));

CREATE UNIQUE INDEX IF NOT EXISTS escalation_items_seq ON escalation_items (tenant_id, seq);
CREATE INDEX IF NOT EXISTS escalation_items_created ON escalation_items (tenant_id, created_at);
-- A second item for the same check (a reused request id with other content) is counted.
CREATE INDEX IF NOT EXISTS escalation_items_check
    ON escalation_items (tenant_id, request_id, guard_point);
CREATE INDEX IF NOT EXISTS escalation_items_resolved ON escalation_items (tenant_id, resolved_at)
    WHERE status = 'resolved';

CREATE OR REPLACE FUNCTION escalation_items_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'escalation_items: TRUNCATE is not allowed'
            USING ERRCODE = 'restrict_violation';
    END IF;
    -- Everything that identifies the item and holds its content never changes.
    IF (NEW.seq, NEW.tenant_id, NEW.id, NEW.request_id, NEW.guard_point, NEW.created_at,
        NEW.target, NEW.reason, NEW.bundle_version, NEW.rules, NEW.content_sha256,
        NEW.store_content, NEW.retention_mode, NEW.content, NEW.content_truncated,
        NEW.triggered_by)
       IS DISTINCT FROM
       (OLD.seq, OLD.tenant_id, OLD.id, OLD.request_id, OLD.guard_point, OLD.created_at,
        OLD.target, OLD.reason, OLD.bundle_version, OLD.rules, OLD.content_sha256,
        OLD.store_content, OLD.retention_mode, OLD.content, OLD.content_truncated,
        OLD.triggered_by) THEN
        RAISE EXCEPTION 'escalation_items: only the resolution and the label may change'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.status = 'open' AND NEW.status = 'resolved'
       AND NEW.label_set_id IS NULL THEN
        RETURN NEW;  -- the resolution, once
    END IF;
    IF OLD.status = 'resolved' AND NEW.status = 'resolved' AND OLD.label_set_id IS NULL
       AND NEW.label_set_id IS NOT NULL
       AND (NEW.decision, NEW.resolution_reason, NEW.resolved_by, NEW.resolved_at)
           IS NOT DISTINCT FROM
           (OLD.decision, OLD.resolution_reason, OLD.resolved_by, OLD.resolved_at) THEN
        RETURN NEW;  -- the label, once
    END IF;
    RAISE EXCEPTION 'escalation_items: that update is not allowed'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER escalation_items_no_other_update
    BEFORE UPDATE ON escalation_items
    FOR EACH ROW EXECUTE FUNCTION escalation_items_guard();
CREATE OR REPLACE TRIGGER escalation_items_no_truncate
    BEFORE TRUNCATE ON escalation_items
    FOR EACH STATEMENT EXECUTE FUNCTION escalation_items_guard();

ALTER TABLE escalation_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_items FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON escalation_items;
CREATE POLICY tenant_scope ON escalation_items
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS escalation_audit (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id     text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    at            timestamptz NOT NULL,
    item_id       text        NOT NULL CHECK (item_id ~ '^esc_[0-9a-f]{24}$'),
    action        text        NOT NULL CHECK (action IN ('resolved', 'label_created')),
    actor         text        NOT NULL CHECK (actor <> '' AND char_length(actor) <= 1024),
    decision      text        CHECK (decision IN ('allow', 'block')),
    reason_sha256 text        CHECK (reason_sha256 ~ '^[0-9a-f]{64}$'),
    label_set_id  text        CHECK (label_set_id ~ '^gs_[0-9a-f]{16}$'),
    label_mode    text        CHECK (label_mode IN ('content', 'hash_only')),
    cross_tenant  boolean     NOT NULL,
    operator      boolean     NOT NULL
);

CREATE INDEX IF NOT EXISTS escalation_audit_by_tenant ON escalation_audit (tenant_id, id);

CREATE OR REPLACE FUNCTION escalation_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'escalation_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER escalation_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON escalation_audit
    FOR EACH ROW EXECUTE FUNCTION escalation_audit_immutable();
CREATE OR REPLACE TRIGGER escalation_audit_no_truncate
    BEFORE TRUNCATE ON escalation_audit
    FOR EACH STATEMENT EXECUTE FUNCTION escalation_audit_immutable();

ALTER TABLE escalation_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON escalation_audit;
CREATE POLICY tenant_scope ON escalation_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- The outbox carries a third kind of event: a notice for a tenant's escalation webhook (024).
ALTER TABLE delivery_outbox DROP CONSTRAINT IF EXISTS delivery_outbox_kind_check;
ALTER TABLE delivery_outbox ADD CONSTRAINT delivery_outbox_kind_check
    CHECK (kind IN ('alert', 'usage', 'escalation'));

-- The class A receipts (026) also record class D deletions, with how many of the deleted items
-- were unresolved (healthcare: they expire 30 days after creation, and the expiry is logged).
ALTER TABLE retention_receipts DROP CONSTRAINT IF EXISTS retention_receipts_retention_class_check;
ALTER TABLE retention_receipts ADD CONSTRAINT retention_receipts_retention_class_check
    CHECK (retention_class IN ('A', 'B', 'D'));
ALTER TABLE retention_receipts DROP CONSTRAINT IF EXISTS retention_receipts_source_check;
ALTER TABLE retention_receipts ADD CONSTRAINT retention_receipts_source_check
    CHECK (source IN ('bundle', 'default', 'clamped', 'fallback', 'healthcare'));
ALTER TABLE retention_receipts
    ADD COLUMN IF NOT EXISTS expired_unresolved integer NOT NULL DEFAULT 0
    CHECK (expired_unresolved >= 0);

-- The only way to delete an escalation item (R3 class D). SECURITY DEFINER with a pinned
-- search_path and schema-qualified tables, exactly as retention_delete_class_b (026),
-- so the retention role needs no DELETE or INSERT grant. Items are under forced row-level
-- security, so it sets the transaction-local tenant setting for the one tenant it was asked
-- about (never a tenant it was not named for).
--
-- **The database, not the caller, decides how long an item lives.** Each item carries
-- the mode it was routed with (retention_mode, fixed by the trigger above): 'resolved_plus' goes
-- when it was resolved before p_now - p_days, so an unresolved item is never deleted; 'total'
-- (healthcare) goes when it was created before it, resolved or not, and counts as expired when it
-- was unresolved. p_mode is validated but does not select anything: naming 'total' deletes
-- nothing that was routed as 'resolved_plus'. Both comparisons are strict. p_days is R3's class D
-- term at least (30) and 400 at most, so no caller can shorten it. p_now is no more than five
-- minutes ahead of the database's clock and is clamped to it, so a mistaken or hostile clock can
-- only delete less. p_limit 1..100000, p_source default | healthcare | fallback. The
-- transaction-local tenant setting is put back as it was before the function returns. A receipt (class D) is written in
-- the same transaction for batch 1 even if nothing was deleted, and for later batches only if
-- they deleted something. Rows another run holds are skipped (FOR UPDATE SKIP LOCKED).
DO $create$
BEGIN
    EXECUTE format($fn$
CREATE OR REPLACE FUNCTION retention_delete_class_d(
    p_run_id    text,
    p_tenant_id text,
    p_now       timestamptz,
    p_mode      text,
    p_days      integer,
    p_source    text,
    p_limit     integer,
    p_batch     integer
) RETURNS TABLE (deleted integer, expired integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
DECLARE
    n         integer;
    e         integer;
    db_now    timestamptz := clock_timestamp();
    v_cutoff  timestamptz;
    v_prev    text := current_setting('app.tenant_id', true);
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'class D batch size must be 1..100000'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_now IS NULL OR p_now > db_now + interval '5 minutes' THEN
        RAISE EXCEPTION 'class D clock is missing or ahead of the database'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_mode IS NULL OR p_mode NOT IN ('resolved_plus', 'total') THEN
        RAISE EXCEPTION 'class D mode must be resolved_plus or total'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_days IS NULL OR p_days < 30 OR p_days > 400 THEN
        RAISE EXCEPTION 'class D days must be 30..400'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_source IS NULL OR p_source NOT IN ('default', 'healthcare', 'fallback') THEN
        RAISE EXCEPTION 'class D source must be default, healthcare or fallback'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_tenant_id IS NULL OR p_tenant_id !~ '^t_[0-9a-z]{1,32}$' THEN
        RAISE EXCEPTION 'class D needs a tenant id' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_cutoff := least(p_now, db_now) - make_interval(days => p_days);
    PERFORM set_config('app.tenant_id', p_tenant_id, true);

    WITH doomed AS (
        SELECT i.tenant_id, i.id, i.status FROM %1$I.escalation_items i
        WHERE i.tenant_id = p_tenant_id
          AND ((i.retention_mode = 'total' AND i.created_at < v_cutoff)
            OR (i.retention_mode = 'resolved_plus' AND i.status = 'resolved'
                AND i.resolved_at < v_cutoff))
        ORDER BY i.seq
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    ), gone AS (
        DELETE FROM %1$I.escalation_items d USING doomed
        WHERE d.tenant_id = doomed.tenant_id AND d.id = doomed.id
        RETURNING doomed.status
    )
    SELECT count(*)::integer, (count(*) FILTER (WHERE status = 'open'))::integer
      INTO n, e FROM gone;

    IF n > 0 OR p_batch = 1 THEN
        INSERT INTO %1$I.retention_receipts
            (run_id, at, tenant_id, retention_class, cutoff, deleted_count, batch,
             retention_days, source, expired_unresolved)
        VALUES (p_run_id, clock_timestamp(), p_tenant_id, 'D', v_cutoff, n, p_batch,
                p_days, p_source, e);
    END IF;
    PERFORM set_config('app.tenant_id', coalesce(v_prev, ''), true);
    RETURN QUERY SELECT n, e;
END;
$body$
    $fn$, current_schema());
END
$create$;

REVOKE ALL ON FUNCTION retention_delete_class_d(
    text, text, timestamptz, text, integer, text, integer, integer) FROM PUBLIC;
