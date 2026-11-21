-- M2-02 drafts: privileges for the role the service connects as (run with 002).
--
-- Run as the table owner with the service's role name in the variable app_role:
--
--     psql -v app_role=guardrail_app -f 009_draft_grants.sql
--
-- or from Python: apply_app_role_grants(owner_pool, "guardrail_app"), which runs 002 and this.
-- The role must not own the tables and must not be a superuser. Safe to run more than once.
--
--   tenant_drafts       SELECT, INSERT, UPDATE   (a draft is replaced; never deleted)
--   tenant_draft_audit  SELECT, INSERT           (append-only; the triggers also refuse the rest)
-- Platform operators reach other tenants' drafts only once the operator pool exists (M2-07),
-- with its own policy; until then 007's operator policy does not cover these tables.

REVOKE ALL ON tenant_drafts, tenant_draft_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE tenant_draft_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT, UPDATE ON tenant_drafts TO :"app_role";
GRANT SELECT, INSERT ON tenant_draft_audit TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE tenant_draft_audit_id_seq TO :"app_role";
