-- M4-09: privileges of the retention job's own database role.
--
-- Run as the table owner, once per retention role (apply_retention_role_grants runs it):
--
--     psql -v retention_role=guardrail_retention -f 030_retention_role_grants.sql
--
-- Create the role first. It must not own the tables, must not be a superuser and should not
-- be the service's application role. It gets no DELETE or INSERT on any table: deletion goes
-- through retention_delete_class_b, which writes the receipt in the same transaction.
--
--   decision_records (tenant_id)   SELECT on that one column (to list the tenants to sweep)
--   retention_receipts             SELECT
--   retention_delete_class_b       EXECUTE
--
-- TEMP is not revoked: every role holds it through PUBLIC, so revoking it from this role alone
-- would do nothing, and revoking it from PUBLIC is a database-wide decision this script (run by
-- the table owner) should not make. It is not needed: retention_delete_class_b pins its own
-- search_path with pg_temp last and schema-qualifies its tables, so a temp table made by this
-- role can't capture a receipt. To remove TEMP anyway:
--   REVOKE TEMPORARY ON DATABASE <db> FROM PUBLIC;  -- then grant it to the roles that need it

REVOKE ALL ON decision_records, retention_receipts FROM :"retention_role";
GRANT SELECT (tenant_id) ON decision_records TO :"retention_role";
GRANT SELECT ON retention_receipts TO :"retention_role";
REVOKE ALL ON FUNCTION retention_delete_class_b(
    text, text, timestamptz, timestamptz, integer, integer, text, integer)
    FROM :"retention_role";
GRANT EXECUTE ON FUNCTION retention_delete_class_b(
    text, text, timestamptz, timestamptz, integer, integer, text, integer)
    TO :"retention_role";
