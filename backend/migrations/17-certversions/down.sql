DROP INDEX idx_cert_versions_serial;
DROP INDEX idx_cert_versions_cert;
DROP TABLE certificate_versions;
ALTER TABLE user_certificates DROP COLUMN fingerprint;
ALTER TABLE user_certificates DROP COLUMN version;
ALTER TABLE user_certificates DROP COLUMN is_imported;
