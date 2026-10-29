CREATE TABLE agents (
    id                      INTEGER PRIMARY KEY,
    account_id              INTEGER NOT NULL,
    agent_uuid              TEXT NOT NULL,
    hostname                TEXT NOT NULL DEFAULT '',
    version                 TEXT NOT NULL DEFAULT '',
    os                      TEXT NOT NULL DEFAULT '',
    arch                    TEXT NOT NULL DEFAULT '',
    schedule                TEXT NOT NULL DEFAULT '',
    heartbeat_interval_sec  INTEGER NOT NULL DEFAULT 300,
    status                  TEXT NOT NULL DEFAULT 'ok',
    error_count             INTEGER NOT NULL DEFAULT 0,
    last_error              TEXT,
    last_error_at           INTEGER,
    soonest_expiry_ms       INTEGER,
    domains_json            TEXT NOT NULL DEFAULT '[]',
    ip                      TEXT NOT NULL DEFAULT '',
    first_seen              INTEGER NOT NULL,
    last_seen               INTEGER NOT NULL,
    FOREIGN KEY(account_id) REFERENCES service_accounts(id) ON DELETE CASCADE,
    UNIQUE(account_id, agent_uuid)
);
CREATE INDEX idx_agents_last_seen ON agents(last_seen);
