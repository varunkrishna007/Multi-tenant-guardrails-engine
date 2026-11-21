-- M2-06 golden sets: privileges for the role the service connects as (run with 002 and 009).
--
--     psql -v app_role=guardrail_app -f 011_golden_grants.sql
--
-- or from Python: apply_app_role_grants(owner_pool, "guardrail_app"), which runs 002, 009 and
-- this. The role must not own the tables and must not be a superuser. Safe to run again.
--
--   tenant_golden_sets, tenant_golden_examples, tenant_golden_audit   SELECT, INSERT
-- Nobody gets UPDATE or DELETE: a set is immutable (the triggers refuse it too).

REVOKE ALL ON tenant_golden_sets, tenant_golden_examples, tenant_golden_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE tenant_golden_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT ON tenant_golden_sets, tenant_golden_examples, tenant_golden_audit
    TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE tenant_golden_audit_id_seq TO :"app_role";
