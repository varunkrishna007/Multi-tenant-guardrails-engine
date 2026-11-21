-- M5-05 operator access to the nightly results, for the platform operator's database role. Run by
-- apply_operator_policy after 007 and 014, with the same operator_role variable:
--
--     psql -v operator_role=guardrail_operator -f 053_nightly_redteam_operator_policies.sql
--
-- The job reads every tenant's active version and writes every tenant's result, and the platform
-- route lists the latest result of every tenant, all as this role. Safe to run again.

DROP POLICY IF EXISTS operator_all ON nightly_redteam_results;
CREATE POLICY operator_all ON nightly_redteam_results
    TO :"operator_role" USING (true) WITH CHECK (true);
