-- M4-09: privileges of the ordinary service role for the retention tables.
--
-- Run as the table owner, once per service role (apply_app_role_grants runs it):
--
--     psql -v app_role=guardrail_app -f 029_retention_app_grants.sql
--
-- Create the role first. It may not own the tables or be a superuser. Safe to run again.
--
--   decision_records     SELECT, INSERT   (insert-only: no UPDATE, no DELETE)
--   decision_record_rules SELECT, INSERT  (M4-07; the same)
--   retention_receipts   nothing          (platform-level; only the retention role reads it)
--   retention_delete_class_b             no EXECUTE: only the retention role may call it

REVOKE ALL ON decision_records, retention_receipts FROM :"app_role";
GRANT SELECT, INSERT ON decision_records TO :"app_role";
-- M4-07: the rule filter's index table (032), insert-only like its record.
REVOKE ALL ON decision_record_rules FROM :"app_role";
GRANT SELECT, INSERT ON decision_record_rules TO :"app_role";
REVOKE ALL ON FUNCTION retention_delete_class_b(
    text, text, timestamptz, timestamptz, integer, integer, text, integer) FROM :"app_role";
