-- M4-03 shadow agreement counters: privileges for the role the service connects as (run with the
-- other grant files by apply_app_role_grants).
--
--     psql -v app_role=guardrail_app -f 031_shadow_grants.sql
--
-- tenant_shadow_agreement   SELECT, INSERT, UPDATE  (counters are added to; nobody deletes)
-- The role must not own the table and must not be a superuser. Safe to run again.

REVOKE ALL ON tenant_shadow_agreement FROM :"app_role";
GRANT SELECT, INSERT, UPDATE ON tenant_shadow_agreement TO :"app_role";
