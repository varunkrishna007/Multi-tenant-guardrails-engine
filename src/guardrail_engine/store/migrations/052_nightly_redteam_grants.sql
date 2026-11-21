-- M5-05: privileges on the nightly red-team results (run with the other grant files by
-- apply_app_role_grants, for the service's role and for the platform operator's role, which is
-- the one the job connects as).
--
--     psql -v app_role=guardrail_operator -f 052_nightly_redteam_grants.sql
--
-- The role must not own the tables and must not be a superuser. Safe to run again.
--
--   nightly_redteam_results   SELECT and INSERT only: no UPDATE (a trigger also refuses it), no
--                             DELETE (only a terminated tenant's offboarding deletes), no TRUNCATE
--   nightly_redteam_quarantine   SELECT and INSERT only (class A, append-only; platform data)

REVOKE ALL ON nightly_redteam_results, nightly_redteam_quarantine FROM :"app_role";
REVOKE ALL ON SEQUENCE nightly_redteam_results_id_seq, nightly_redteam_quarantine_id_seq
    FROM :"app_role";
GRANT SELECT, INSERT ON nightly_redteam_results, nightly_redteam_quarantine TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE nightly_redteam_results_id_seq, nightly_redteam_quarantine_id_seq
    TO :"app_role";
