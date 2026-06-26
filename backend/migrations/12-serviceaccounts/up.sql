CREATE TABLE service_accounts (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    secret_hash  TEXT NOT NULL,
    user_id      INTEGER NOT NULL,
    scopes       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_service_accounts_client_id ON service_accounts(client_id);
