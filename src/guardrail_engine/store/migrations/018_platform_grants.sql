-- M2-09 platform tables: privileges for the role the service connects as (run with 002, 009, 011,
-- 013, 016).
--
--     psql -v app_role=guardrail_app -f 018_platform_grants.sql
--
-- or from Python: apply_app_role_grants(owner_pool, "guardrail_app"), which runs all of them.
-- The role must not own the tables and must not be a superuser. Safe to run again.
--
--   platform_floor_releases     SELECT, INSERT, UPDATE (released_at, security_urgent, halted)
--   platform_floor_approvals    SELECT, INSERT                  (append-only)
--   platform_floor_state        SELECT, INSERT, UPDATE
--   platform_audit              SELECT, INSERT                  (append-only)

REVOKE ALL ON platform_floor_releases, platform_floor_approvals, platform_floor_state,
    platform_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE platform_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT ON platform_floor_releases TO :"app_role";
GRANT UPDATE (released_at, security_urgent, halted) ON platform_floor_releases TO :"app_role";
GRANT SELECT, INSERT ON platform_floor_approvals TO :"app_role";
GRANT SELECT, INSERT, UPDATE ON platform_floor_state TO :"app_role";
GRANT SELECT, INSERT ON platform_audit TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE platform_audit_id_seq TO :"app_role";
