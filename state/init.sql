CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE bgp_updates (
    time        TIMESTAMPTZ NOT NULL,
    prefix      TEXT NOT NULL,
    peer        TEXT,
    peer_asn    BIGINT,
    type        TEXT NOT NULL,
    as_path     JSONB,
    origin_asn  BIGINT,
    path_length INTEGER,
    next_hop    TEXT
);

SELECT create_hypertable('bgp_updates', 'time');

CREATE INDEX ON bgp_updates (prefix, time DESC);

CREATE TABLE bgp_anomalies (
    time            TIMESTAMPTZ NOT NULL,
    prefix          TEXT NOT NULL,
    type            TEXT NOT NULL,
    peer            TEXT,
    peer_asn        BIGINT,
    old_origin_asn  BIGINT,
    new_origin_asn  BIGINT,
    as_path         JSONB,
    anomaly_score   DOUBLE PRECISION,
    triggered_rules JSONB
);

SELECT create_hypertable('bgp_anomalies', 'time');

CREATE INDEX ON bgp_anomalies (prefix, time DESC);
