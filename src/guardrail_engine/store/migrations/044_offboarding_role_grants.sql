-- M5-07: privileges of the retention job's own database role for offboarding.
-- Run as the table owner, after 043, once per retention role (apply_retention_role_grants runs it
-- with 030 and 037):
--
--     psql -v retention_role=guardrail_retention -f 044_offboarding_role_grants.sql
--
-- The role gets no DELETE or INSERT on any table: deletion goes through
-- offboarding_delete_batch, which refuses any tenant whose status is not 'terminated' (the
-- database checks, not the caller) and writes its receipt in the same transaction; the completion
-- receipt through offboarding_complete. It reads the tenants waiting through offboarding_pending
-- (so it needs no grant on the directory) and the receipts directly.
--
--   offboarding_receipts, offboarding_completions, offboarding_usage_summaries,
--   offboarding_sweeps   SELECT
--   offboarding_pending, offboarding_delete_batch, offboarding_complete,
--   offboarding_resweep_pending, offboarding_sweep_log   EXECUTE
--
-- offboarding_delete_allowed (the triggers' test) is not granted: the role has no use for it.
-- The service's application role gets nothing here (EXECUTE is revoked from PUBLIC by 043).

REVOKE ALL ON offboarding_receipts, offboarding_completions, offboarding_usage_summaries,
    offboarding_sweeps FROM :"retention_role";
GRANT SELECT ON offboarding_receipts, offboarding_completions, offboarding_usage_summaries,
    offboarding_sweeps TO :"retention_role";
REVOKE ALL ON FUNCTION offboarding_pending(integer) FROM :"retention_role";
REVOKE ALL ON FUNCTION offboarding_delete_batch(text, text, text, integer, integer, numeric)
    FROM :"retention_role";
REVOKE ALL ON FUNCTION offboarding_complete(text, text, timestamptz) FROM :"retention_role";
REVOKE ALL ON FUNCTION offboarding_resweep_pending(timestamptz, integer) FROM :"retention_role";
REVOKE ALL ON FUNCTION offboarding_sweep_log(text, text, integer, bigint, timestamptz)
    FROM :"retention_role";
GRANT EXECUTE ON FUNCTION offboarding_pending(integer) TO :"retention_role";
GRANT EXECUTE ON FUNCTION offboarding_delete_batch(text, text, text, integer, integer, numeric)
    TO :"retention_role";
GRANT EXECUTE ON FUNCTION offboarding_complete(text, text, timestamptz) TO :"retention_role";
GRANT EXECUTE ON FUNCTION offboarding_resweep_pending(timestamptz, integer)
    TO :"retention_role";
GRANT EXECUTE ON FUNCTION offboarding_sweep_log(text, text, integer, bigint, timestamptz)
    TO :"retention_role";
