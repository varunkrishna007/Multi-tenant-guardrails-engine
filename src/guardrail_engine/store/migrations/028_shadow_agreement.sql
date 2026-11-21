-- M4-03 progressive rollout: what a shadow candidate did, compared with the active version.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after
-- 006 (row-level security). 029 gives the application role its privileges.
--
-- Counters only: per tenant, active version, candidate version and rule, how often the two
-- versions called for the same action and how often the candidate called for a stricter or a
-- looser one. **No probability and no content is stored**, so the report built from it can't
-- show a floor rule's p (a gradient to tune content under its threshold). The row with
-- rule_key '*decision*' counts the overall decision, the row '*summary*' the checks compared
-- and the ones that could not be (the candidate or the active version gave no rule answers, or
-- the provider refused the candidate, PF-12).
CREATE TABLE IF NOT EXISTS tenant_shadow_agreement (
    tenant_id          text   NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    active_version     bigint NOT NULL CHECK (active_version >= 1),
    candidate_version  bigint NOT NULL CHECK (candidate_version >= 1),
    rule_key           text   NOT NULL CHECK (rule_key <> '' AND length(rule_key) <= 128),
    layer              text   NOT NULL DEFAULT '',
    n                  bigint NOT NULL DEFAULT 0 CHECK (n >= 0),
    agree              bigint NOT NULL DEFAULT 0 CHECK (agree >= 0),
    candidate_stricter bigint NOT NULL DEFAULT 0 CHECK (candidate_stricter >= 0),
    candidate_looser   bigint NOT NULL DEFAULT 0 CHECK (candidate_looser >= 0),
    only_active        bigint NOT NULL DEFAULT 0 CHECK (only_active >= 0),
    only_candidate     bigint NOT NULL DEFAULT 0 CHECK (only_candidate >= 0),
    checks             bigint NOT NULL DEFAULT 0 CHECK (checks >= 0),
    incomparable       bigint NOT NULL DEFAULT 0 CHECK (incomparable >= 0),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, active_version, candidate_version, rule_key)
);

ALTER TABLE tenant_shadow_agreement ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_shadow_agreement FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_shadow_agreement;
CREATE POLICY tenant_scope ON tenant_shadow_agreement
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
