-- M5-01: the regulated-tier attribute's audit action.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 043.
--
-- tenant_directory_audit.action gains 'set_tier': a change of the tier attribute made by
-- TenantProvisioner.set_tier (M5-01). Class A, as every directory write: the actor, the before
-- and the after (and the operator's reason), append-only (004).
--
-- tenants is platform data, written only by operators and read by the Guard Service by id (004),
-- so it is not row-level secured; nothing here adds a tenant-scoped table.

ALTER TABLE tenant_directory_audit DROP CONSTRAINT IF EXISTS tenant_directory_audit_action_check;
ALTER TABLE tenant_directory_audit ADD CONSTRAINT tenant_directory_audit_action_check
    CHECK (action IN ('create', 'update', 'set_status', 'set_tier', 'terminating', 'terminated'));
