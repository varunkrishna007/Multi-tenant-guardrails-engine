-- M5-02 two-person approval: privileges for the role the service connects as (run with the other
-- grant files by apply_app_role_grants).
--
--     psql -v app_role=guardrail_app -f 041_approval_grants.sql
--
-- The role must not own the tables and must not be a superuser. Safe to run again.
--
--   tenant_approvals       SELECT, INSERT, and UPDATE on the status columns only (the trigger in
--                          040 allows just the moves pending -> approved -> consumed and
--                          pending or approved -> cancelled or expired); no DELETE
--   tenant_approval_audit  SELECT, INSERT (append-only; triggers refuse the rest)

REVOKE ALL ON tenant_approvals, tenant_approval_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE tenant_approval_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT ON tenant_approvals, tenant_approval_audit TO :"app_role";
GRANT UPDATE (status, expires_at, approved_by, approved_at, consumed_by, consumed_at, closed_at,
              close_reason) ON tenant_approvals TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE tenant_approval_audit_id_seq TO :"app_role";
