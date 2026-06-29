CREATE TABLE acme_client_providers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    directory_url TEXT NOT NULL,
    account_email TEXT NOT NULL DEFAULT '',
    eab_kid TEXT,
    eab_hmac_key BLOB,
    account_credentials TEXT,
    created_on INTEGER NOT NULL
);

CREATE TABLE acme_client_orders (
    id INTEGER PRIMARY KEY,
    provider_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    include_wildcard INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending_dns',
    order_url TEXT,
    txt_records TEXT NOT NULL DEFAULT '[]',
    cert_id INTEGER,
    error TEXT,
    created_on INTEGER NOT NULL,
    expires_at INTEGER,
    FOREIGN KEY(provider_id) REFERENCES acme_client_providers(id) ON DELETE CASCADE,
    FOREIGN KEY(cert_id) REFERENCES user_certificates(id) ON DELETE SET NULL
);

ALTER TABLE user_certificates ADD COLUMN acme_provider_id INTEGER REFERENCES acme_client_providers(id) ON DELETE SET NULL;

CREATE INDEX idx_acme_client_orders_provider ON acme_client_orders(provider_id, created_on);

INSERT INTO acme_client_providers (name, directory_url, account_email, created_on)
VALUES
  ('Let''s Encrypt (production)', 'https://acme-v02.api.letsencrypt.org/directory', '', 0),
  ('Let''s Encrypt (staging)', 'https://acme-staging-v02.api.letsencrypt.org/directory', '', 0);
