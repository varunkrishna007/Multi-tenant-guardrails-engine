-- M7-08 an escalation caused by a provider refusal names the rules it might have been about.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after 034.
-- No new privilege: the service's role already has SELECT and INSERT on the table.
--
-- When the provider refuses to judge content, no rule answered, so ``rules`` (the rules that
-- fired) is empty. At a guard point where a rule may only escalate, the item goes to a person
-- anyway, and ``candidate_rules`` holds the keys of those escalate-only rules, so the reviewer
-- sees why it landed in their queue. Keys only: never a score, never the provider's text. Like the
-- rest of what identifies the item, it never changes once written.

ALTER TABLE escalation_items
    ADD COLUMN IF NOT EXISTS candidate_rules jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE escalation_items DROP CONSTRAINT IF EXISTS escalation_items_candidate_rules_check;
ALTER TABLE escalation_items ADD CONSTRAINT escalation_items_candidate_rules_check
    CHECK (jsonb_typeof(candidate_rules) = 'array');

CREATE OR REPLACE FUNCTION escalation_items_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'escalation_items: TRUNCATE is not allowed'
            USING ERRCODE = 'restrict_violation';
    END IF;
    -- Everything that identifies the item and holds its content never changes.
    IF (NEW.seq, NEW.tenant_id, NEW.id, NEW.request_id, NEW.guard_point, NEW.created_at,
        NEW.target, NEW.reason, NEW.bundle_version, NEW.rules, NEW.candidate_rules,
        NEW.content_sha256, NEW.store_content, NEW.retention_mode, NEW.content,
        NEW.content_truncated, NEW.triggered_by)
       IS DISTINCT FROM
       (OLD.seq, OLD.tenant_id, OLD.id, OLD.request_id, OLD.guard_point, OLD.created_at,
        OLD.target, OLD.reason, OLD.bundle_version, OLD.rules, OLD.candidate_rules,
        OLD.content_sha256, OLD.store_content, OLD.retention_mode, OLD.content,
        OLD.content_truncated, OLD.triggered_by) THEN
        RAISE EXCEPTION 'escalation_items: only the resolution and the label may change'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.status = 'open' AND NEW.status = 'resolved'
       AND NEW.label_set_id IS NULL THEN
        RETURN NEW;  -- the resolution, once
    END IF;
    IF OLD.status = 'resolved' AND NEW.status = 'resolved' AND OLD.label_set_id IS NULL
       AND NEW.label_set_id IS NOT NULL
       AND (NEW.decision, NEW.resolution_reason, NEW.resolved_by, NEW.resolved_at)
           IS NOT DISTINCT FROM
           (OLD.decision, OLD.resolution_reason, OLD.resolved_by, OLD.resolved_at) THEN
        RETURN NEW;  -- the label, once
    END IF;
    RAISE EXCEPTION 'escalation_items: that update is not allowed'
        USING ERRCODE = 'restrict_violation';
END;
$$;
