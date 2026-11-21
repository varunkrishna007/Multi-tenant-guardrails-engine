-- M5-02 two-person approval (R2): the approval requests and the class A trail of what happened
-- to them. 041 gives the service role its privileges, 042 the operator role's policies.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role, after 006
-- (row-level security) and 012 (the lifecycle tables, whose per-tenant advisory lock the
-- service holds for every write below).
--
-- tenant_approvals: one row per request. An approval is tied to a draft hash (a ``publish``
-- approval) or to the draft hash and version of a candidate (a ``promote`` approval), is made
-- by a different actor than the requester, expires, and is used once. **Insert-only except for
-- the status**: the service role has no DELETE and only a column-level UPDATE on the status
-- columns, and the trigger below allows exactly these moves and nothing else:
--     pending  -> approved   (approver, time and the new expiry set together)
--     approved -> consumed   (by the publish or promotion that used it, once)
--     pending or approved -> cancelled | expired
-- Every other column never changes, a terminal row never moves again, and a row can't be
-- deleted or truncated. The database also refuses an approval by the requester itself.
--
-- tenant_approval_audit (R3 class A): every request, approval, cancellation, expiry-at-use,
-- consumption and admin notification, with the actor. Append-only.

CREATE TABLE IF NOT EXISTS tenant_approvals (
    tenant_id     text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    id            text        NOT NULL CHECK (id ~ '^apr_[0-9a-f]{24}$'),
    action        text        NOT NULL CHECK (action IN ('publish', 'promote')),
    draft_hash    text        NOT NULL CHECK (draft_hash ~ '^sha256:[0-9a-f]{64}$'),
    version       bigint      CHECK (version >= 1),
    requested_by  text        NOT NULL CHECK (requested_by <> '' AND char_length(requested_by) <= 1024),
    requested_at  timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    status        text        NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'approved', 'consumed', 'cancelled', 'expired')),
    approved_by   text        CHECK (approved_by <> '' AND char_length(approved_by) <= 1024),
    approved_at   timestamptz,
    consumed_by   text        CHECK (consumed_by <> '' AND char_length(consumed_by) <= 1024),
    consumed_at   timestamptz,
    closed_at     timestamptz,
    close_reason  text        CHECK (char_length(close_reason) <= 200),
    PRIMARY KEY (tenant_id, id),
    -- A promote approval names the candidate version; a publish approval names none.
    CHECK ((action = 'promote') = (version IS NOT NULL)),
    CHECK (expires_at > requested_at),
    -- Never by the requester (R2): the database refuses it too.
    CHECK (approved_by IS NULL OR approved_by <> requested_by),
    -- Nor does the approver spend it: the requester may publish, the approver may not.
    CHECK (consumed_by IS NULL OR consumed_by <> approved_by),
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CHECK ((consumed_by IS NULL) = (consumed_at IS NULL)),
    CHECK (status <> 'pending' OR (approved_by IS NULL AND consumed_by IS NULL
                                   AND closed_at IS NULL)),
    CHECK (status NOT IN ('approved', 'consumed') OR approved_by IS NOT NULL),
    CHECK ((status = 'consumed') = (consumed_by IS NOT NULL)),
    CHECK ((status IN ('cancelled', 'expired')) = (closed_at IS NOT NULL)),
    CHECK (close_reason IS NULL OR closed_at IS NOT NULL),
    CHECK (status <> 'approved' OR (consumed_by IS NULL AND closed_at IS NULL))
);

CREATE INDEX IF NOT EXISTS tenant_approvals_open ON tenant_approvals (tenant_id, requested_at)
    WHERE status IN ('pending', 'approved');
-- The list route: newest request first, paged by (requested_at, id).
CREATE INDEX IF NOT EXISTS tenant_approvals_by_request
    ON tenant_approvals (tenant_id, requested_at DESC, id DESC);

CREATE OR REPLACE FUNCTION tenant_approvals_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'tenant_approvals: % is not allowed', TG_OP
            USING ERRCODE = 'restrict_violation';
    END IF;
    -- What identifies the approval and what it is for never changes.
    IF (NEW.tenant_id, NEW.id, NEW.action, NEW.draft_hash, NEW.version, NEW.requested_by,
        NEW.requested_at)
       IS DISTINCT FROM
       (OLD.tenant_id, OLD.id, OLD.action, OLD.draft_hash, OLD.version, OLD.requested_by,
        OLD.requested_at) THEN
        RAISE EXCEPTION 'tenant_approvals: only the status columns may change'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.status = 'pending' AND NEW.status = 'approved'
       AND NEW.approved_by IS NOT NULL AND NEW.approved_at IS NOT NULL
       AND NEW.consumed_by IS NULL AND NEW.closed_at IS NULL AND NEW.close_reason IS NULL THEN
        RETURN NEW;  -- approved, with its own expiry
    END IF;
    IF OLD.status = 'approved' AND NEW.status = 'consumed'
       AND (NEW.approved_by, NEW.approved_at, NEW.expires_at)
           IS NOT DISTINCT FROM (OLD.approved_by, OLD.approved_at, OLD.expires_at)
       AND NEW.consumed_by IS NOT NULL AND NEW.closed_at IS NULL THEN
        RETURN NEW;  -- used, once
    END IF;
    IF OLD.status IN ('pending', 'approved') AND NEW.status IN ('cancelled', 'expired')
       AND (NEW.approved_by, NEW.approved_at, NEW.expires_at)
           IS NOT DISTINCT FROM (OLD.approved_by, OLD.approved_at, OLD.expires_at)
       AND NEW.consumed_by IS NULL AND NEW.closed_at IS NOT NULL THEN
        RETURN NEW;  -- cancelled by a draft edit, or found expired when it was used
    END IF;
    RAISE EXCEPTION 'tenant_approvals: that status change is not allowed'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER tenant_approvals_no_other_change
    BEFORE UPDATE OR DELETE ON tenant_approvals
    FOR EACH ROW EXECUTE FUNCTION tenant_approvals_guard();
CREATE OR REPLACE TRIGGER tenant_approvals_no_truncate
    BEFORE TRUNCATE ON tenant_approvals
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_approvals_guard();

ALTER TABLE tenant_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_approvals;
CREATE POLICY tenant_scope ON tenant_approvals
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS tenant_approval_audit (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id    text        NOT NULL CHECK (tenant_id ~ '^t_[0-9a-z]{1,32}$'),
    at           timestamptz NOT NULL,
    approval_id  text        CHECK (approval_id ~ '^apr_[0-9a-f]{24}$'),
    action       text        NOT NULL
                 CHECK (action IN ('requested', 'approved', 'cancelled', 'expired', 'consumed',
                                   'notified')),
    actor        text        NOT NULL CHECK (actor <> '' AND char_length(actor) <= 1024),
    draft_hash   text        CHECK (draft_hash ~ '^sha256:[0-9a-f]{64}$'),
    version      bigint      CHECK (version >= 1),
    detail       text        NOT NULL DEFAULT '' CHECK (char_length(detail) <= 500),
    cross_tenant boolean     NOT NULL,
    operator     boolean     NOT NULL
);

CREATE INDEX IF NOT EXISTS tenant_approval_audit_by_tenant ON tenant_approval_audit (tenant_id, id);

CREATE OR REPLACE FUNCTION tenant_approval_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tenant_approval_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE TRIGGER tenant_approval_audit_no_update_or_delete
    BEFORE UPDATE OR DELETE ON tenant_approval_audit
    FOR EACH ROW EXECUTE FUNCTION tenant_approval_audit_immutable();
CREATE OR REPLACE TRIGGER tenant_approval_audit_no_truncate
    BEFORE TRUNCATE ON tenant_approval_audit
    FOR EACH STATEMENT EXECUTE FUNCTION tenant_approval_audit_immutable();

ALTER TABLE tenant_approval_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_approval_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON tenant_approval_audit;
CREATE POLICY tenant_scope ON tenant_approval_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
