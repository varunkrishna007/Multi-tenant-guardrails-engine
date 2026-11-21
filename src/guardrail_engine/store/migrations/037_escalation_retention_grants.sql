-- M4-05: privileges of the retention job's own database role for class D (escalation items).
-- Run as the table owner, after 030, once per retention role (apply_retention_role_grants runs it
-- with 030):
--
--     psql -v retention_role=guardrail_retention -f 037_escalation_retention_grants.sql
--
-- The role gets no DELETE or INSERT on any table: deletion goes through
-- retention_delete_class_d, which writes the receipt in the same transaction.
--
--   escalation_items (tenant_id)   SELECT on that one column, through a policy that lets this role
--                                  see every row's tenant (to list the tenants to sweep); the
--                                  content and everything else stay unreadable to it
--   retention_delete_class_d       EXECUTE

REVOKE ALL ON escalation_items FROM :"retention_role";
GRANT SELECT (tenant_id) ON escalation_items TO :"retention_role";
DROP POLICY IF EXISTS class_d_tenants ON escalation_items;
CREATE POLICY class_d_tenants ON escalation_items FOR SELECT
    TO :"retention_role" USING (true);
REVOKE ALL ON FUNCTION retention_delete_class_d(
    text, text, timestamptz, text, integer, text, integer, integer) FROM :"retention_role";
GRANT EXECUTE ON FUNCTION retention_delete_class_d(
    text, text, timestamptz, text, integer, text, integer, integer) TO :"retention_role";
