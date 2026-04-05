CREATE TABLE IF NOT EXISTS dns_queries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    client_ip     TEXT NOT NULL,
    client_name   TEXT,
    domain        TEXT NOT NULL,
    query_type    TEXT NOT NULL,
    blocked       INTEGER NOT NULL DEFAULT 0,
    blocked_rule  TEXT,
    category      TEXT,
    resolved_ip   TEXT,
    response_ms   INTEGER
);

CREATE INDEX idx_timestamp ON dns_queries(timestamp);
CREATE INDEX idx_domain    ON dns_queries(domain);
CREATE INDEX idx_blocked      ON dns_queries(blocked);
CREATE INDEX idx_client_name  ON dns_queries(client_name);

CREATE TABLE IF NOT EXISTS blocklist_meta (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name     TEXT NOT NULL UNIQUE,
    last_synced_at  TEXT NOT NULL,
    domain_count    INTEGER NOT NULL
);
