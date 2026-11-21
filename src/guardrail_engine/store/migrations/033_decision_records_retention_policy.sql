-- M4-07: the retention job's role reads the tenant ids of decision_records (a column grant,
-- 030) to list whom to sweep. Row-level security (032) would show it no row, so it gets a
-- SELECT policy. The column grant still limits it to ``tenant_id``.
--
-- Run as the table owner, once per retention role (apply_retention_role_grants runs it):
--
--     psql -v retention_role=guardrail_retention -f 033_decision_records_retention_policy.sql
--
-- Safe to run again.

DROP POLICY IF EXISTS retention_tenants ON decision_records;
CREATE POLICY retention_tenants ON decision_records FOR SELECT
    TO :"retention_role" USING (true);
