-- M5-06: a tenant's dedicated Gemini project (key pool), and usage attributable per project.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 038 (which gave usage_events forced row-level security) and 045. The grants of 005 already
-- cover the new tenants column (table-level SELECT, INSERT, UPDATE for the platform writer;
-- SELECT for the Guard Service's reader), and 025 the usage table's, so there is no grants file.
--
--   1. tenants.project: the label of the dedicated Gemini project the tenant is assigned to,
--      NULL for the shared pool. A label only: a key is never stored. The label's shape is
--      checked here as well as in code, and one tenant may hold a given project at a time (a
--      terminating or terminated tenant gives its project up, so the label can be reassigned;
--      such a row can't change any more, 043). tenants is platform data (004): not
--      row-level secured, written only by operators, read by the Guard Service by id.
--   2. usage_events.project: the label of the project whose key made the metered call, '' for
--      the shared pool's default project (and for a row written before this migration). A label
--      only, never a key or a project secret. usage_events is tenant-scoped and stays under the
--      forced row-level security of 038 (tenant_read, tenant_insert; 014 for the operator's
--      read): a tenant's metrics see their own project label, and no other tenant's.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS project text;
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_project_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_project_check
    CHECK (project IS NULL OR (project ~ '^[a-z0-9][a-z0-9-]{0,39}$' AND project <> 'default'));

CREATE UNIQUE INDEX IF NOT EXISTS tenants_dedicated_project_unique
    ON tenants (project)
    WHERE project IS NOT NULL AND status NOT IN ('terminating', 'terminated');

ALTER TABLE usage_events ADD COLUMN IF NOT EXISTS project text NOT NULL DEFAULT '';
ALTER TABLE usage_events DROP CONSTRAINT IF EXISTS usage_events_project_check;
ALTER TABLE usage_events ADD CONSTRAINT usage_events_project_check
    CHECK (project = '' OR project ~ '^[a-z0-9][a-z0-9-]{0,39}$');

-- The table stays under forced row-level security (038); stated again so that this migration
-- can't be read as relaxing it.
ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS usage_events_tenant_project_time
    ON usage_events (tenant_id, project, occurred_at);
