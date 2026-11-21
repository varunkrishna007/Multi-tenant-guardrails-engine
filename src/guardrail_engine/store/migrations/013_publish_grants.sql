-- M2-07 lifecycle: privileges for the role the service connects as (run with 002, 009, 011).
--
--     psql -v app_role=guardrail_app -f 013_publish_grants.sql
--
-- or from Python: apply_app_role_grants(owner_pool, "guardrail_app"), which runs all of them.
-- The role must not own the tables and must not be a superuser. Safe to run again.
--
--   tenant_candidates      SELECT, INSERT, UPDATE, DELETE   (the one candidate moves and ends)
--   tenant_publish_audit   SELECT, INSERT                   (append-only; triggers refuse the rest)

REVOKE ALL ON tenant_candidates, tenant_publish_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE tenant_publish_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_candidates TO :"app_role";
GRANT SELECT, INSERT ON tenant_publish_audit TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE tenant_publish_audit_id_seq TO :"app_role";
