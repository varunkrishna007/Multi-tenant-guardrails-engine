-- M5-03 stored content: privileges for the role the service connects as (run with the other
-- grant files by apply_app_role_grants).
--
--     psql -v app_role=guardrail_app -f 048_stored_content_grants.sql
--
-- The role must not own the tables and must not be a superuser. Safe to run again.
--
--   stored_content   SELECT and INSERT only: no UPDATE (a trigger also refuses it), no DELETE
--                    (only the retention role's function deletes), no TRUNCATE
--   stored_content_audit   SELECT and INSERT only (class A, append-only)
--   retention_delete_class_c   no EXECUTE: only the retention role may call it

REVOKE ALL ON stored_content, stored_content_audit FROM :"app_role";
REVOKE ALL ON SEQUENCE stored_content_audit_id_seq FROM :"app_role";
GRANT SELECT, INSERT ON stored_content, stored_content_audit TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE stored_content_audit_id_seq TO :"app_role";
REVOKE ALL ON FUNCTION retention_delete_class_c(text, text, timestamptz, integer, integer)
    FROM :"app_role";
