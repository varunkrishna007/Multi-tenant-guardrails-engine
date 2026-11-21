-- M2-07 operator access to the tenant tables added after 007 (the drafts, golden sets and
-- lifecycle tables), for the platform operator's database role. Run by apply_operator_policy
-- after 007, with the same operator_role variable:
--
--     psql -v operator_role=guardrail_operator -f 014_operator_policies.sql
--
-- The operator role also needs the table grants (apply_app_role_grants for that role). The Admin
-- API connects as it only for a request its authorizer allowed across tenants (a TenantScope
-- with ``operator`` set); every other request uses the tenant-scoped application role. Safe to
-- run more than once.

DROP POLICY IF EXISTS operator_all ON tenant_drafts;
CREATE POLICY operator_all ON tenant_drafts
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_draft_audit;
CREATE POLICY operator_all ON tenant_draft_audit
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_golden_sets;
CREATE POLICY operator_all ON tenant_golden_sets
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_golden_examples;
CREATE POLICY operator_all ON tenant_golden_examples
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_golden_audit;
CREATE POLICY operator_all ON tenant_golden_audit
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_candidates;
CREATE POLICY operator_all ON tenant_candidates
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_publish_audit;
CREATE POLICY operator_all ON tenant_publish_audit
    TO :"operator_role" USING (true) WITH CHECK (true);

-- 015 (the tool registry, M2-03).
DROP POLICY IF EXISTS operator_all ON tenant_tools;
CREATE POLICY operator_all ON tenant_tools
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_tool_audit;
CREATE POLICY operator_all ON tenant_tool_audit
    TO :"operator_role" USING (true) WITH CHECK (true);

-- 020 (calibration, M4-01).
DROP POLICY IF EXISTS operator_all ON tenant_calibration_targets;
CREATE POLICY operator_all ON tenant_calibration_targets
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_calibration_scores;
CREATE POLICY operator_all ON tenant_calibration_scores
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_calibration_outcomes;
CREATE POLICY operator_all ON tenant_calibration_outcomes
    TO :"operator_role" USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS operator_all ON tenant_calibration_audit;
CREATE POLICY operator_all ON tenant_calibration_audit
    TO :"operator_role" USING (true) WITH CHECK (true);

-- 028 (the shadow agreement counters, M4-03).
DROP POLICY IF EXISTS operator_all ON tenant_shadow_agreement;
CREATE POLICY operator_all ON tenant_shadow_agreement
    TO :"operator_role" USING (true) WITH CHECK (true);

-- 032 (M4-07): a platform operator reads any tenant's decision records. Read only: the
-- policy is for SELECT, so the operator role cannot write a row it can't also name a tenant for.
DROP POLICY IF EXISTS operator_read ON decision_records;
CREATE POLICY operator_read ON decision_records FOR SELECT
    TO :"operator_role" USING (true);
DROP POLICY IF EXISTS operator_read ON decision_record_rules;
CREATE POLICY operator_read ON decision_record_rules FOR SELECT
    TO :"operator_role" USING (true);

-- 038 (M4-06): a platform operator reads any tenant's usage rows.
DROP POLICY IF EXISTS operator_read ON usage_events;
CREATE POLICY operator_read ON usage_events FOR SELECT
    TO :"operator_role" USING (true);
