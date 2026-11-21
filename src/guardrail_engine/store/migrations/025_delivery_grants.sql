-- M4-04 durable delivery: privileges for the service role.
--
-- Run as the table owner, once per service role:
--
--     psql -v app_role=guardrail_app -f 025_delivery_grants.sql
--
-- or through apply_app_role_grants (it runs this file with the others). Create the role
-- first. It may not own the tables or be a superuser. Safe to run more than once.
--
--   delivery_outbox  SELECT, INSERT, UPDATE, DELETE (DELETE only purges delivered events)
--   usage_events     SELECT, INSERT (usage rows are never changed or removed by the service)

REVOKE ALL ON delivery_outbox, usage_events FROM :"app_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON delivery_outbox TO :"app_role";
GRANT SELECT, INSERT ON usage_events TO :"app_role";
