-- M4-05 operator access to the escalation tables, for the platform operator's database role. Run
-- by apply_operator_policy after 007 and 014, with the same operator_role variable:
--
--     psql -v operator_role=guardrail_operator -f 036_escalation_operator_policies.sql
--
-- The operator role also needs the table grants (apply_app_role_grants for that role). The Admin
-- API connects as it only for a request its authorizer allowed across tenants. Safe to run again.

DROP POLICY IF EXISTS operator_all ON escalation_items;
CREATE POLICY operator_all ON escalation_items
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON escalation_audit;
CREATE POLICY operator_all ON escalation_audit
    TO :"operator_role" USING (true) WITH CHECK (true);
