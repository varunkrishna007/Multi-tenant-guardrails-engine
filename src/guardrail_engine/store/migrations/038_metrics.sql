-- M4-06 metrics and cost attribution: what the metrics query aggregates, and the tenant scoping
-- of the usage store.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 024 and 032.
--
-- 1. decision_records gets three columns copied from the record when it is written, so a
--    window's latency percentiles, tokens and versions are read from columns and never from the
--    JSON text: ``latency_ms``, ``input_tokens`` and ``bundle_version``. A row written before
--    this migration has them NULL and is left out of those figures (the check count still
--    includes it).
-- 2. decision_record_rules gets ``action``, ``layer`` and ``mode`` of the fired entry, so "how
--    often did rule X block or escalate" is a group-by on the rule's own index.
-- 3. usage_events (024, platform-level until now) is tenant-scoped: forced row-level
--    security, the service role reads and writes only the rows of the tenant its transaction's
--    app.tenant_id names, like every tenant table (006). The outbox dispatcher writes each
--    event under its tenant's setting. A platform operator reads any tenant's rows (014).

ALTER TABLE decision_records ADD COLUMN IF NOT EXISTS latency_ms real;
ALTER TABLE decision_records ADD COLUMN IF NOT EXISTS input_tokens integer
    CHECK (input_tokens IS NULL OR input_tokens >= 0);
ALTER TABLE decision_records ADD COLUMN IF NOT EXISTS bundle_version integer;

ALTER TABLE decision_record_rules ADD COLUMN IF NOT EXISTS action text;
ALTER TABLE decision_record_rules ADD COLUMN IF NOT EXISTS layer text;
ALTER TABLE decision_record_rules ADD COLUMN IF NOT EXISTS mode text;

ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_read ON usage_events;
CREATE POLICY tenant_read ON usage_events FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_insert ON usage_events;
CREATE POLICY tenant_insert ON usage_events FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
