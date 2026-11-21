-- M2-01 platform-operator access across tenants (AC-T1: only platform operators can cross
-- tenants, and every cross-tenant access is audited by the Admin API's authorizer).
--
-- Run as the table owner with the operator database role's name:
--
--     psql -v operator_role=guardrail_operator -f 007_rls_operator_policy.sql
--
-- or from Python: apply_operator_policy(owner_pool, "guardrail_operator"). The role must exist,
-- must not be a superuser or own the tables, and also needs the 002 grants
-- (apply_app_role_grants). The Admin API connects as this role only for a request that its
-- authorizer allowed across tenants; every other request uses the tenant-scoped application
-- role. Safe to run more than once.

DROP POLICY IF EXISTS operator_all ON policy_bundle_versions;
CREATE POLICY operator_all ON policy_bundle_versions
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON policy_active_versions;
CREATE POLICY operator_all ON policy_active_versions
    TO :"operator_role" USING (true) WITH CHECK (true);
