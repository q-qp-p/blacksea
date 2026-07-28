-- records table — §3.1 field set, exactly mirroring the Record dict assembled by assembly.py.
-- observed_source is flattened to three columns (source_ip, source_ja3, source_type) for
-- direct SQL filtering without jsonb operators. signals and details are jsonb.

CREATE TABLE IF NOT EXISTS records (
    -- §3.1 identity / routing
    record_id        text        PRIMARY KEY,
    bait_id          text        NOT NULL,
    bait_version     text        NOT NULL,
    instance_token   text        NOT NULL,   -- 16-char hex (8 B)
    campaign_id      text        NOT NULL,
    assurance_tier   smallint    NOT NULL,   -- 0 | 1 | 2
    deploy_class     text        NOT NULL,   -- portable_artifact | host_resident | interactive_service

    -- §3.1 session correlation
    session_id       text        NOT NULL,   -- 16-char hex (8 B)
    seq_no           integer     NOT NULL,
    event_type       text        NOT NULL,

    -- §3.1 timestamps
    edge_recv_time   bigint      NOT NULL,   -- ms, observed-tier (inv 17)
    sensor_time      bigint      NOT NULL,   -- ms, claimed-tier

    -- §3.1 observed source (flattened from the observed_source struct)
    source_ip        text        NOT NULL,
    source_ja3       text,                   -- null for DNS / non-TLS channels
    source_type      text        NOT NULL,   -- "client" | "resolver"

    -- §3.1 integrity / provenance
    sig_valid        boolean     NOT NULL,
    channel          text        NOT NULL,
    edge_id          text        NOT NULL,

    -- §3.1 status flags
    orphan           boolean     NOT NULL    DEFAULT false,
    instance_status  text        NOT NULL,
    design_status    text        NOT NULL,
    test             boolean     NOT NULL    DEFAULT false,  -- from a test/example/reference bait, not real intel

    -- §3.4 signals — optional promoted fields; Tier-2 reads these, never details
    signals          jsonb,

    -- §3.5 details — opaque bait-specific intel; Tier-2 never reads this (inv 12)
    details          jsonb,
    details_truncated boolean    NOT NULL    DEFAULT false,

    -- housekeeping
    ingested_at      timestamptz NOT NULL    DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_records_bait_id        ON records (bait_id);
CREATE INDEX IF NOT EXISTS idx_records_instance_token ON records (instance_token);
CREATE INDEX IF NOT EXISTS idx_records_campaign_id    ON records (campaign_id);
CREATE INDEX IF NOT EXISTS idx_records_session_id     ON records (session_id);
CREATE INDEX IF NOT EXISTS idx_records_edge_recv_time ON records (edge_recv_time);

-- brain_health — the brain liveness heartbeat. The pool upserts this
-- single row every heartbeat cycle so `blacksea status` can turn the brain — the one component
-- that can silently stop consuming — from an inferred guess into a directly-known fact. It lives
-- in the brain's OWN (public) schema, next to `records` which the brain already writes; it must
-- NOT go in the control_plane schema, where brain_role is SELECT-only (it could not write there).
-- A one-row singleton (id is pinned to 1) — the latest poll wins.
CREATE TABLE IF NOT EXISTS brain_health (
    id            smallint    PRIMARY KEY DEFAULT 1,
    last_poll_at  timestamptz NOT NULL,
    consumer_lag  bigint,                            -- optional JetStream lag; NULL until wired
    CONSTRAINT brain_health_singleton CHECK (id = 1)
);
