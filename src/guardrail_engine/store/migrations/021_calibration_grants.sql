-- M4-01 calibration: privileges for the role the service connects as (run with 002 and the
-- other grant files by apply_app_role_grants).
--
--     psql -v app_role=guardrail_app -f 021_calibration_grants.sql
--
-- The role must not own the tables and must not be a superuser. Safe to run again.
--
--   tenant_calibration_targets   SELECT, INSERT, UPDATE  (a tenant's targets are replaced;
--                                every change is also a row of the audit table)
--   tenant_calibration_scores, tenant_calibration_outcomes    SELECT, INSERT
--   tenant_calibration_audit     SELECT, INSERT
-- Nobody gets DELETE; the triggers refuse UPDATE and DELETE on the last two.

REVOKE ALL ON tenant_calibration_targets, tenant_calibration_scores, tenant_calibration_outcomes,
    tenant_calibration_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE tenant_calibration_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT, UPDATE ON tenant_calibration_targets TO :"app_role";
GRANT SELECT, INSERT ON tenant_calibration_scores, tenant_calibration_outcomes,
    tenant_calibration_audit TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE tenant_calibration_audit_id_seq TO :"app_role";
