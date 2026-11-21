-- M2-01 tenant directory: privileges for its two service roles.
--
-- Run as the table owner, with both role names:
--
--     psql -v reader_role=guardrail_app -v writer_role=guardrail_platform \
--          -f 005_directory_grants.sql
--
-- or from Python: apply_directory_grants(owner_pool, reader, writer). Create the roles first.
-- Neither may own the tables or be a superuser. Safe to run more than once.
--
--   reader (the Guard Service)     tenants SELECT
--   writer (the platform API)      tenants SELECT, INSERT, UPDATE; audit SELECT, INSERT
-- Nobody gets DELETE: a tenant is offboarded (status), never removed.

REVOKE ALL ON tenants, tenant_directory_audit FROM :"reader_role", :"writer_role";
REVOKE ALL ON SEQUENCE tenant_directory_audit_id_seq FROM :"reader_role", :"writer_role";
GRANT SELECT ON tenants TO :"reader_role";
GRANT SELECT, INSERT, UPDATE ON tenants TO :"writer_role";
GRANT SELECT, INSERT ON tenant_directory_audit TO :"writer_role";
GRANT USAGE, SELECT ON SEQUENCE tenant_directory_audit_id_seq TO :"writer_role";
