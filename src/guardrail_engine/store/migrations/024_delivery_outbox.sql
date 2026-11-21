-- M4-04 durable delivery: the outbox for alert and metering events, and the usage store.
--
-- Plain SQL, safe to run more than once, PostgreSQL 14 or later. Run as the owner role.
-- Privileges for the service role are in 025_delivery_grants.sql.
--
-- delivery_outbox: an event is inserted pending, claimed under a lease (locked_until) by a
-- dispatcher, and ends delivered or dead (dead-lettered after the retry policy's attempts).
-- Delivery is at least once; idempotency_key is the same on every retry and is what the
-- receiver de-duplicates on. The payload is the event as JSON text: an alert (a fixed
-- sentence and identifiers) or a usage record (tenant, guard point, token count). Never
-- content, and never a secret.
--
-- These tables are platform-level, not tenant-scoped: an alert may be about the whole
-- platform, and usage rows carry the tenant id as data. They have no row-level security.

CREATE TABLE IF NOT EXISTS delivery_outbox (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    idempotency_key  text        NOT NULL UNIQUE
                     CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    kind             text        NOT NULL CHECK (kind IN ('alert', 'usage')),
    payload          text        NOT NULL CHECK (char_length(payload) <= 65536),
    state            text        NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending', 'delivered', 'dead')),
    attempts         integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at       timestamptz NOT NULL,
    next_attempt_at  timestamptz NOT NULL,
    locked_until     timestamptz,
    last_error       text        CHECK (char_length(last_error) <= 200),
    delivered_at     timestamptz,
    dead_at          timestamptz
);

CREATE INDEX IF NOT EXISTS delivery_outbox_due
    ON delivery_outbox (next_attempt_at, id) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS delivery_outbox_delivered
    ON delivery_outbox (delivered_at) WHERE state = 'delivered';

-- usage_events: the usage store. One row per metering event; the primary key is the outbox
-- event's idempotency key, so a second delivery of the same event is a no-op. input_tokens
-- is NULL when it is unknown (never zero).
CREATE TABLE IF NOT EXISTS usage_events (
    idempotency_key  text        PRIMARY KEY
                     CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    kind             text        NOT NULL CHECK (kind IN (
                         'answered', 'unknown', 'unanswered', 'provider_safety',
                         'model_skipped', 'patterns_dropped')),
    tenant_id        text        NOT NULL,
    guard_point      text        NOT NULL,
    input_tokens     bigint      CHECK (input_tokens IS NULL OR input_tokens >= 0),
    occurred_at      timestamptz NOT NULL,
    recorded_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS usage_events_tenant_time ON usage_events (tenant_id, occurred_at);
