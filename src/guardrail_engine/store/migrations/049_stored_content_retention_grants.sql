-- M5-03: privileges of the retention job's own database role for class C (stored content). Run
-- as the table owner, after 030, once per retention role (apply_retention_role_grants runs it
-- with 030):
--
--     psql -v retention_role=guardrail_retention -f 049_stored_content_retention_grants.sql
--
-- The role gets no DELETE or INSERT on any table: deletion goes through
-- retention_delete_class_c, which writes the receipt in the same transaction.
--
--   stored_content (tenant_id)   SELECT on that one column, through a policy that lets this role
--                                see every row's tenant (to list the tenants to sweep); the
--                                content and everything else stay unreadable to it
--   retention_delete_class_c     EXECUTE

REVOKE ALL ON stored_content FROM :"retention_role";
GRANT SELECT (tenant_id) ON stored_content TO :"retention_role";
DROP POLICY IF EXISTS class_c_tenants ON stored_content;
CREATE POLICY class_c_tenants ON stored_content FOR SELECT
    TO :"retention_role" USING (true);
REVOKE ALL ON FUNCTION retention_delete_class_c(text, text, timestamptz, integer, integer)
    FROM :"retention_role";
GRANT EXECUTE ON FUNCTION retention_delete_class_c(text, text, timestamptz, integer, integer)
    TO :"retention_role";
