DROP INDEX IF EXISTS idx_acme_client_orders_provider;
DROP TABLE IF EXISTS acme_client_orders;
DROP TABLE IF EXISTS acme_client_providers;
-- SQLite не умеет DROP COLUMN в старых версиях; колонка acme_provider_id остаётся (безопасно).
