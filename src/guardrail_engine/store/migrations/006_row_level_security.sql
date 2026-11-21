-- M2-01 row-level security for the policy store (AC-T1): tenant isolation in the database
-- itself, so a bug, a forged filter or a query without a WHERE clause still cannot read or
-- write another tenant's bundles.
--
-- The policy compares each row's tenant_id with the transaction-local setting app.tenant_id,
-- which the store sets from the verified tenant (the signed context or the verified token)
-- with set_config('app.tenant_id', $1, true), never from a request body. When the setting is
-- missing the comparison is NULL and no row is visible or writable. FORCE makes the policy
-- apply to the table owner too (a superuser still bypasses RLS: the service must never
-- connect as one, and 002_app_role_grants.sql already requires that).
--
-- Not applied to the tenant directory (platform data, 004). Platform operators reach every
-- tenant through a separate database role: 007_rls_operator_policy.sql.
-- Safe to run more than once.

ALTER TABLE policy_bundle_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_bundle_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON policy_bundle_versions;
CREATE POLICY tenant_scope ON policy_bundle_versions
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE policy_active_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_active_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON policy_active_versions;
CREATE POLICY tenant_scope ON policy_active_versions
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
