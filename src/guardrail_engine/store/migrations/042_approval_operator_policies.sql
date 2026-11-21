-- M5-02 operator access to the approval tables, for the platform operator's database role. Run
-- by apply_operator_policy after 007 and 014, with the same operator_role variable:
--
--     psql -v operator_role=guardrail_operator -f 042_approval_operator_policies.sql
--
-- The operator role also needs the table grants (apply_app_role_grants for that role). The Admin
-- API connects as it only for a request its authorizer allowed across tenants. An operator
-- publishing into a tenant uses an approval (and so updates it), like any lifecycle write; the
-- service refuses an operator's approval before it reaches the table (R2), and the CHECK and
-- trigger in 040 refuse a self-approval whoever the role is. Safe to run again.

DROP POLICY IF EXISTS operator_all ON tenant_approvals;
CREATE POLICY operator_all ON tenant_approvals
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_approval_audit;
CREATE POLICY operator_all ON tenant_approval_audit
    TO :"operator_role" USING (true) WITH CHECK (true);
