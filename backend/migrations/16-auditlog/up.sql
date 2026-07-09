CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    actor_id     INTEGER,
    actor_label  TEXT NOT NULL,
    actor_type   TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT,
    target_id    TEXT,
    target_label TEXT,
    result       TEXT NOT NULL,
    detail       TEXT,
    ip           TEXT
);

CREATE INDEX idx_audit_ts ON audit_log(ts);
CREATE INDEX idx_audit_actor ON audit_log(actor_id);
CREATE INDEX idx_audit_action ON audit_log(action);
