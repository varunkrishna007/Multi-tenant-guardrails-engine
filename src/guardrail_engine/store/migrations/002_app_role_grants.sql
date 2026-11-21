-- M1-02 policy store: privileges for the role the service connects as.
--
-- Run as the role that owns the tables (the one that ran 001_policy_store.sql), with the
-- service's role name in the variable app_role:
--
--     psql -v app_role=guardrail_app -f 002_app_role_grants.sql
--
-- or from Python: apply_app_role_grants(owner_pool, "guardrail_app").
--
-- Create the role yourself first (CREATE ROLE guardrail_app LOGIN ...); this file sets no
-- password. The role must not own the tables, must not be a superuser, and needs USAGE on
-- the schema the tables are in. Safe to run more than once.
--
-- What the role ends up with is exactly what the store uses:
--   policy_bundle_versions   SELECT, INSERT           (never UPDATE, DELETE or TRUNCATE)
--   policy_active_versions   SELECT, INSERT, UPDATE   (the pointer moves; it is never deleted)
-- Not owning the tables, it cannot ALTER them, so it cannot disable or drop the
-- immutability triggers.

REVOKE ALL ON policy_bundle_versions, policy_active_versions FROM :"app_role";
GRANT SELECT, INSERT ON policy_bundle_versions TO :"app_role";
GRANT SELECT, INSERT, UPDATE ON policy_active_versions TO :"app_role";
