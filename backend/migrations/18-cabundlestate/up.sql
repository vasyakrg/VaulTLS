-- Wall-clock timestamp of the last membership change in the imported-TLS CA
-- set (the public CA bundle). Serves as the bundle's Last-Modified, which
-- cannot be derived from the current rows: certificates carry their notBefore
-- as created_on, so deleting an imported CA would move Last-Modified backwards
-- and leave If-Modified-Since clients on a stale 304.
CREATE TABLE IF NOT EXISTS ca_bundle_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    modified_ms INTEGER NOT NULL
);

-- Seed with the pre-migration approximation (max notBefore of imported CAs, 0
-- when none) so the upgrade itself does not invalidate existing caches; the
-- triggers keep the value monotonic from then on.
INSERT OR IGNORE INTO ca_bundle_state (id, modified_ms)
    SELECT 1, COALESCE(MAX(created_on), 0)
    FROM ca_certificates WHERE is_imported = 1 AND type = 0;

-- MAX() keeps the stamp monotonic even if the host clock steps backwards.
CREATE TRIGGER IF NOT EXISTS ca_bundle_state_touch_insert
    AFTER INSERT ON ca_certificates
    FOR EACH ROW WHEN NEW.is_imported = 1 AND NEW.type = 0
BEGIN
    INSERT INTO ca_bundle_state (id, modified_ms)
        VALUES (1, CAST(strftime('%s', 'now') AS INTEGER) * 1000)
    ON CONFLICT(id) DO UPDATE SET modified_ms =
        MAX(ca_bundle_state.modified_ms, excluded.modified_ms);
END;

CREATE TRIGGER IF NOT EXISTS ca_bundle_state_touch_delete
    AFTER DELETE ON ca_certificates
    FOR EACH ROW WHEN OLD.is_imported = 1 AND OLD.type = 0
BEGIN
    INSERT INTO ca_bundle_state (id, modified_ms)
        VALUES (1, CAST(strftime('%s', 'now') AS INTEGER) * 1000)
    ON CONFLICT(id) DO UPDATE SET modified_ms =
        MAX(ca_bundle_state.modified_ms, excluded.modified_ms);
END;

-- Membership can also flip in place. Plain attribute updates (CRL number
-- bumps) must NOT touch the stamp — the WHEN clause keeps them out.
CREATE TRIGGER IF NOT EXISTS ca_bundle_state_touch_update
    AFTER UPDATE ON ca_certificates
    FOR EACH ROW WHEN OLD.is_imported != NEW.is_imported OR OLD.type != NEW.type
BEGIN
    INSERT INTO ca_bundle_state (id, modified_ms)
        VALUES (1, CAST(strftime('%s', 'now') AS INTEGER) * 1000)
    ON CONFLICT(id) DO UPDATE SET modified_ms =
        MAX(ca_bundle_state.modified_ms, excluded.modified_ms);
END;
