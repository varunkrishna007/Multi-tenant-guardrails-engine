-- M7-04 a decision record spilled to disk can be replayed once: the key it is replayed under.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 032. No new privilege is needed: the service's role already inserts into the table.
--
-- A regulated tenant's record that finds the writer's queue full is spilled to a local file and
-- written to this table later (audit/spill.py). If the engine stops after the insert and before
-- it marks the spilled line done, the record is replayed. ``record_key`` is the id the record
-- was spilled with, so the second insert is skipped. Per tenant, and only for records that have
-- one: every other record has no key and never conflicts. The column is a copy of what the
-- writer was given; it is not in the record's JSON.

ALTER TABLE decision_records ADD COLUMN IF NOT EXISTS record_key text
    CHECK (record_key IS NULL OR char_length(record_key) BETWEEN 1 AND 64);

CREATE UNIQUE INDEX IF NOT EXISTS decision_records_tenant_record_key
    ON decision_records (tenant_id, record_key) WHERE record_key IS NOT NULL;
