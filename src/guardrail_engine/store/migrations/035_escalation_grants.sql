-- M4-05 escalation queue: privileges for the role the service connects as (run with the other
-- grant files by apply_app_role_grants).
--
--     psql -v app_role=guardrail_app -f 035_escalation_grants.sql
--
-- The role must not own the tables and must not be a superuser. Safe to run again.
--
--   escalation_items   SELECT, INSERT, and UPDATE on the resolution and label columns only (the
--                      trigger in 034 allows just open -> resolved and the label, once each);
--                      no DELETE: only the retention role's function deletes
--   escalation_audit   SELECT, INSERT (append-only)
--   retention_delete_class_d   no EXECUTE: only the retention role may call it

REVOKE ALL ON escalation_items, escalation_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE escalation_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT ON escalation_items, escalation_audit TO :"app_role";
GRANT UPDATE (status, decision, resolution_reason, resolved_by, resolved_at, label_set_id,
              label_mode) ON escalation_items TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE escalation_audit_id_seq TO :"app_role";
REVOKE ALL ON FUNCTION retention_delete_class_d(
    text, text, timestamptz, text, integer, text, integer, integer) FROM :"app_role";
