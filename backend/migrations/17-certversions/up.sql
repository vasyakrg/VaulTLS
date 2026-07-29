ALTER TABLE user_certificates ADD COLUMN is_imported INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_certificates ADD COLUMN version     INTEGER NOT NULL DEFAULT 1;
ALTER TABLE user_certificates ADD COLUMN fingerprint TEXT;

CREATE TABLE certificate_versions (
    id          INTEGER PRIMARY KEY,
    cert_id     INTEGER NOT NULL REFERENCES user_certificates(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    data        BLOB NOT NULL,
    password    TEXT NOT NULL DEFAULT '',
    created_on  INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    serial_hex  TEXT,
    ca_id       INTEGER,
    fingerprint TEXT NOT NULL,
    replaced_at INTEGER NOT NULL,
    replaced_by INTEGER,
    UNIQUE(cert_id, version)
);

CREATE INDEX idx_cert_versions_cert ON certificate_versions(cert_id);
CREATE INDEX idx_cert_versions_serial ON certificate_versions(serial_hex);

-- Backfill: mark a leaf as imported only when it could not possibly have been
-- issued here. An imported CA that carries a private key CAN issue locally
-- (get_latest_tls_ca happily signs with it), so leaves under it may well be
-- internally issued and must keep auto-renewing. Only an imported CA WITHOUT a
-- usable key proves every leaf under it came from outside. Absent key follows
-- the codebase convention CA::has_private_key() == !key.is_empty().
UPDATE user_certificates SET is_imported = 1
 WHERE acme_provider_id IS NULL
   AND ca_id IN (
       SELECT id FROM ca_certificates
        WHERE is_imported = 1 AND (key IS NULL OR length(key) = 0)
   );
