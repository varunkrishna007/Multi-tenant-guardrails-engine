-- M2-03 tool registry: privileges for the role the service connects as (run with 002, 009, 011,
-- 013).
--
--     psql -v app_role=guardrail_app -f 016_tool_grants.sql
--
-- or from Python: apply_app_role_grants(owner_pool, "guardrail_app"), which runs all of them.
-- The role must not own the tables and must not be a superuser. Safe to run again.
--
--   tenant_tools        SELECT, INSERT, UPDATE, DELETE   (entries are edited, reviewed, deleted)
--   tenant_tool_audit   SELECT, INSERT                   (append-only; triggers refuse the rest)

REVOKE ALL ON tenant_tools, tenant_tool_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE tenant_tool_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_tools TO :"app_role";
GRANT SELECT, INSERT ON tenant_tool_audit TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE tenant_tool_audit_id_seq TO :"app_role";
