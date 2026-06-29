# ACME / Let's Encrypt Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Дать VaulTLS возможность получать публичные TLS-сертификаты от Let's Encrypt (и совместимых ACME-CA) через ручной dns-01: сгенерировать TXT-записи, дождаться ручного внесения в bind9, выпустить и сохранить сертификат для скачивания.

**Architecture:** Новый backend-модуль `backend/src/acme_client/` на базе крейта `instant-acme` (ACME-клиент, не путать с существующим `backend/src/acme/` — ACME-сервером). Двухфазный поток: фаза 1 создаёт заказ и возвращает TXT-записи; фаза 2 после ручного ввода в DNS делает предпроверку резолвером и завершает выдачу. Сертификаты пишутся в существующую таблицу `user_certificates` (`ca_id = NULL`, `acme_provider_id` = провайдер). Управление — новая Vue-вкладка «Let's Encrypt».

**Tech Stack:** Rust + Rocket + rusqlite (SQLCipher, пул через `r2d2`), `instant-acme` (rustls + aws-lc-rs), `hickory-resolver`; Vue 3 + Pinia + PrimeVue.

## Global Constraints

- БД целиком шифруется (`encrypted.db3`); секреты хранятся как обычные колонки (по образцу `acme_accounts.eab_hmac_key: BLOB`). Отдельного пошифрового шифрования не добавлять.
- Имена таблиц/типов клиента — префикс `acme_client_*` / `AcmeClient*`, чтобы не конфликтовать с серверными `acme_*` / `Acme*`.
- БД-методы пишутся через макрос `db_do!(self.pool, |conn: &Connection| { ... })`; время — `SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64`.
- Маршруты: `#[openapi(tag = "ACME Client")]`, guard `AuthenticatedPrivileged` (admin-only), `state: &State<AppState>`, ошибки `ApiError`. Регистрируются во ВСЕХ трёх блоках `openapi_get_routes!` в `backend/src/lib.rs` (их три — строки ~191, ~268, ~311).
- Crypto-provider для `instant-acme` и rustls — `aws_lc_rs` (уже используется в проекте).
- Миграции — каталог `backend/migrations/NN-<name>/` с файлами `up.sql` и `down.sql`; следующий номер — **13**.
- Frontend: запросы через `ApiClient` (`/api` базовый); локализация в `src/locales/en.json` и `src/locales/es.json` (`fr.json` пустой — не трогать).
- Проверки: backend — `cd backend && cargo test`; типы фронта — `cd frontend && npx vue-tsc --noEmit`.

---

## Файловая структура

**Создаются:**
- `backend/migrations/13-acmeclient/up.sql`, `down.sql` — схема + seed пресетов LE
- `backend/src/acme_client/mod.rs` — реэкспорт модуля
- `backend/src/acme_client/types.rs` — доменные типы и request/response DTO
- `backend/src/acme_client/client.rs` — обёртка над `instant-acme` (фазы 1 и 2)
- `backend/src/acme_client/routes.rs` — HTTP-маршруты
- `backend/src/dns_check.rs` — общий резолвер-helper (вынесен из `acme/routes.rs`)
- `frontend/src/types/AcmeClient.ts` — TS-типы
- `frontend/src/api/acmeClient.ts` — API-клиент
- `frontend/src/stores/acmeClient.ts` — Pinia store
- `frontend/src/components/AcmeClientTab.vue` — UI вкладки

**Модифицируются:**
- `backend/Cargo.toml` — зависимость `instant-acme`
- `backend/src/lib.rs` — `mod acme_client; mod dns_check;` + регистрация маршрутов
- `backend/src/db.rs` — CRUD-методы провайдеров и заказов, row-мапперы
- `backend/src/acme/routes.rs` — использовать общий `dns_check`
- `backend/src/notification/notifier.rs` — напоминание об истечении LE-сертов
- `frontend/src/router/index.ts` — маршрут `/letsencrypt`
- `frontend/src/components/Sidebar.vue` — пункт меню
- `frontend/src/components/OverviewTab.vue` — `caName` показывает провайдера для LE-сертов
- `frontend/src/locales/en.json`, `es.json` — строки

---

## Task 1: Зависимость `instant-acme`

**Files:**
- Modify: `backend/Cargo.toml`

**Interfaces:**
- Produces: доступность крейта `instant_acme` (типы `Account`, `NewAccount`, `NewOrder`, `Identifier`, `ChallengeType`, `LetsEncrypt`, `RetryPolicy`, `ExternalAccountKey`, `AccountCredentials`).

- [ ] **Step 1: Добавить зависимость**

В `backend/Cargo.toml` в секцию `[dependencies]` добавить строку (рядом с `rustls`):

```toml
instant-acme = { version = "0.8", default-features = false, features = ["aws-lc-rs"] }
```

- [ ] **Step 2: Проверить, что версия/фичи резолвятся и собирается**

Run: `cd backend && cargo add instant-acme --dry-run` затем `cargo build`
Expected: сборка проходит. Если фича `aws-lc-rs` называется иначе в установленной версии — выполнить `cargo add instant-acme` без `--dry-run`, посмотреть доступные features в выводе и выставить ту, что включает `aws-lc-rs` backend. Зафиксировать реальную версию в `Cargo.toml`.

- [ ] **Step 3: Commit**

```bash
git add backend/Cargo.toml backend/Cargo.lock
git commit -m "build: add instant-acme dependency for ACME client"
```

---

## Task 2: Миграция 13 — таблицы клиента + колонка + seed LE

**Files:**
- Create: `backend/migrations/13-acmeclient/up.sql`
- Create: `backend/migrations/13-acmeclient/down.sql`

**Interfaces:**
- Produces: таблицы `acme_client_providers`, `acme_client_orders`; колонка `user_certificates.acme_provider_id`; две seed-строки провайдеров LE (production, staging) с `account_credentials = NULL`.

- [ ] **Step 1: Написать тест миграции**

В `backend/src/db.rs` в `mod tests` (рядом с другими `#[tokio::test]`) добавить:

```rust
#[tokio::test]
async fn migration_13_creates_acme_client_tables_and_le_presets() {
    let db = mem_db().await;
    let providers = db.get_all_acme_client_providers().await.unwrap();
    // Two Let's Encrypt presets seeded
    assert_eq!(providers.len(), 2);
    assert!(providers.iter().any(|p| p.directory_url.contains("acme-v02.api.letsencrypt.org")));
    assert!(providers.iter().any(|p| p.directory_url.contains("acme-staging-v02.api.letsencrypt.org")));
    // Orders table exists and is empty
    let orders = db.get_all_acme_client_orders().await.unwrap();
    assert_eq!(orders.len(), 0);
}
```

(Тест не скомпилируется без методов из Task 4/5 — это ожидаемо; на этом шаге проверяем именно схему через шаг 2, а компиляцию теста завершаем в Task 5.)

- [ ] **Step 2: Создать `up.sql`**

`backend/migrations/13-acmeclient/up.sql`:

```sql
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
```

- [ ] **Step 3: Создать `down.sql`**

`backend/migrations/13-acmeclient/down.sql`:

```sql
DROP INDEX IF EXISTS idx_acme_client_orders_provider;
DROP TABLE IF EXISTS acme_client_orders;
DROP TABLE IF EXISTS acme_client_providers;
-- SQLite не умеет DROP COLUMN в старых версиях; колонка acme_provider_id остаётся (безопасно).
```

- [ ] **Step 4: Проверить, что миграции применяются**

Run: `cd backend && cargo build`
Expected: сборка проходит (миграции встраиваются через `include_dir!`; реальное применение проверится тестами в Task 5).

- [ ] **Step 5: Commit**

```bash
git add backend/migrations/13-acmeclient
git commit -m "feat(db): migration 13 — acme_client tables + LE presets"
```

---

## Task 3: Доменные типы клиента

**Files:**
- Create: `backend/src/acme_client/mod.rs`
- Create: `backend/src/acme_client/types.rs`
- Modify: `backend/src/lib.rs` (добавить `mod acme_client;`)

**Interfaces:**
- Produces:
  - `struct AcmeClientProvider { id: i64, name: String, directory_url: String, account_email: String, eab_kid: Option<String>, eab_hmac_key: Option<Vec<u8>>, account_credentials: Option<String>, created_on: i64 }`
  - `struct AcmeClientOrder { id: i64, provider_id: i64, domain: String, include_wildcard: bool, status: String, order_url: Option<String>, txt_records: Vec<TxtRecord>, cert_id: Option<i64>, error: Option<String>, created_on: i64, expires_at: Option<i64> }`
  - `struct TxtRecord { name: String, value: String }`
  - DTO: `CreateProviderRequest`, `CreateOrderRequest`, `CreateOrderResponse`.

- [ ] **Step 1: Написать unit-тест сериализации `TxtRecord`**

В `backend/src/acme_client/types.rs` (внизу):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_records_json_roundtrip() {
        let recs = vec![
            TxtRecord { name: "_acme-challenge.example.com".into(), value: "abc".into() },
            TxtRecord { name: "_acme-challenge.example.com".into(), value: "def".into() },
        ];
        let json = serde_json::to_string(&recs).unwrap();
        let back: Vec<TxtRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[1].value, "def");
    }
}
```

- [ ] **Step 2: Запустить тест — убедиться, что не компилируется (типов нет)**

Run: `cd backend && cargo test acme_client::types`
Expected: ошибка компиляции (модуль/типы отсутствуют).

- [ ] **Step 3: Создать модуль и типы**

`backend/src/acme_client/mod.rs`:

```rust
pub mod types;
pub mod client;
pub mod routes;
```

`backend/src/acme_client/types.rs`:

```rust
use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
pub struct TxtRecord {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct AcmeClientProvider {
    pub id: i64,
    pub name: String,
    pub directory_url: String,
    pub account_email: String,
    pub eab_kid: Option<String>,
    #[serde(skip)]
    pub eab_hmac_key: Option<Vec<u8>>,
    #[serde(skip)]
    pub account_credentials: Option<String>,
    pub created_on: i64,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct AcmeClientOrder {
    pub id: i64,
    pub provider_id: i64,
    pub domain: String,
    pub include_wildcard: bool,
    pub status: String,
    pub order_url: Option<String>,
    pub txt_records: Vec<TxtRecord>,
    pub cert_id: Option<i64>,
    pub error: Option<String>,
    pub created_on: i64,
    pub expires_at: Option<i64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateProviderRequest {
    pub name: String,
    pub directory_url: String,
    pub account_email: String,
    /// base64url EAB key id (для ZeroSSL/BuyPass), опционально
    pub eab_kid: Option<String>,
    /// base64url EAB HMAC key, опционально
    pub eab_hmac_key: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateOrderRequest {
    pub provider_id: i64,
    pub domain: String,
    pub include_wildcard: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateOrderResponse {
    pub order_id: i64,
    pub txt_records: Vec<TxtRecord>,
}
```

В `backend/src/lib.rs` добавить рядом с другими `mod` объявлениями:

```rust
mod acme_client;
```

- [ ] **Step 4: Запустить тест — должен пройти**

Run: `cd backend && cargo test acme_client::types`
Expected: PASS (`client`/`routes` пока пустые — добавить в них временно `// placeholder` чтобы модуль компилировался; реальное содержимое в Task 8–11). Для компиляции создать `client.rs` и `routes.rs` с пустым содержимым (один комментарий).

- [ ] **Step 5: Commit**

```bash
git add backend/src/acme_client backend/src/lib.rs
git commit -m "feat(acme-client): domain types and DTOs"
```

---

## Task 4: DB-методы — провайдеры (CRUD)

**Files:**
- Modify: `backend/src/db.rs`

**Interfaces:**
- Consumes: `AcmeClientProvider`, `CreateProviderRequest` из Task 3.
- Produces (методы `VaulTLSDB`):
  - `async fn get_all_acme_client_providers(&self) -> Result<Vec<AcmeClientProvider>>`
  - `async fn get_acme_client_provider(&self, id: i64) -> Result<AcmeClientProvider>`
  - `async fn insert_acme_client_provider(&self, name: String, directory_url: String, account_email: String, eab_kid: Option<String>, eab_hmac_key: Option<Vec<u8>>) -> Result<AcmeClientProvider>`
  - `async fn update_acme_client_provider_credentials(&self, id: i64, account_credentials: String) -> Result<()>`
  - `async fn delete_acme_client_provider(&self, id: i64) -> Result<()>`

- [ ] **Step 1: Написать тест провайдеров**

В `backend/src/db.rs` `mod tests`:

```rust
#[tokio::test]
async fn acme_client_provider_crud() {
    let db = mem_db().await;
    let p = db.insert_acme_client_provider(
        "Test CA".into(), "https://acme.example/dir".into(), "a@b.c".into(), None, None,
    ).await.unwrap();
    assert!(p.id > 0);
    db.update_acme_client_provider_credentials(p.id, "{\"k\":1}".into()).await.unwrap();
    let got = db.get_acme_client_provider(p.id).await.unwrap();
    assert_eq!(got.account_credentials.as_deref(), Some("{\"k\":1}"));
    db.delete_acme_client_provider(p.id).await.unwrap();
    // presets (2) remain
    let all = db.get_all_acme_client_providers().await.unwrap();
    assert_eq!(all.len(), 2);
}
```

- [ ] **Step 2: Запустить — fail (методов нет)**

Run: `cd backend && cargo test acme_client_provider_crud`
Expected: ошибка компиляции (методы отсутствуют).

- [ ] **Step 3: Реализовать методы и маппер**

В `backend/src/db.rs` добавить use (если нет): `use crate::acme_client::types::{AcmeClientProvider, AcmeClientOrder, TxtRecord};` и методы в `impl VaulTLSDB`:

```rust
pub(crate) async fn insert_acme_client_provider(
    &self,
    name: String,
    directory_url: String,
    account_email: String,
    eab_kid: Option<String>,
    eab_hmac_key: Option<Vec<u8>>,
) -> Result<AcmeClientProvider> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let id = db_do!(self.pool, |conn: &Connection| {
        conn.execute(
            "INSERT INTO acme_client_providers (name, directory_url, account_email, eab_kid, eab_hmac_key, created_on) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, directory_url, account_email, eab_kid, eab_hmac_key, now],
        )?;
        Ok::<i64, anyhow::Error>(conn.last_insert_rowid())
    })?;
    self.get_acme_client_provider(id).await
}

pub(crate) async fn get_acme_client_provider(&self, id: i64) -> Result<AcmeClientProvider> {
    db_do!(self.pool, |conn: &Connection| {
        Ok(conn.query_row(
            "SELECT id, name, directory_url, account_email, eab_kid, eab_hmac_key, account_credentials, created_on \
             FROM acme_client_providers WHERE id = ?1",
            params![id],
            acme_client_provider_from_row,
        )?)
    })
}

pub(crate) async fn get_all_acme_client_providers(&self) -> Result<Vec<AcmeClientProvider>> {
    db_do!(self.pool, |conn: &Connection| {
        let mut stmt = conn.prepare(
            "SELECT id, name, directory_url, account_email, eab_kid, eab_hmac_key, account_credentials, created_on \
             FROM acme_client_providers ORDER BY id ASC",
        )?;
        let rows = stmt.query([])?;
        Ok(rows.mapped(acme_client_provider_from_row).collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

pub(crate) async fn update_acme_client_provider_credentials(&self, id: i64, account_credentials: String) -> Result<()> {
    db_do!(self.pool, |conn: &Connection| {
        conn.execute(
            "UPDATE acme_client_providers SET account_credentials = ?1 WHERE id = ?2",
            params![account_credentials, id],
        )?;
        Ok::<(), anyhow::Error>(())
    })
}

pub(crate) async fn delete_acme_client_provider(&self, id: i64) -> Result<()> {
    db_do!(self.pool, |conn: &Connection| {
        conn.execute("DELETE FROM acme_client_providers WHERE id = ?1", params![id])?;
        Ok::<(), anyhow::Error>(())
    })
}
```

Маппер (рядом с `acme_account_from_row`, вне `impl`):

```rust
fn acme_client_provider_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AcmeClientProvider> {
    Ok(AcmeClientProvider {
        id: row.get(0)?,
        name: row.get(1)?,
        directory_url: row.get(2)?,
        account_email: row.get(3)?,
        eab_kid: row.get(4)?,
        eab_hmac_key: row.get(5)?,
        account_credentials: row.get(6)?,
        created_on: row.get(7)?,
    })
}
```

- [ ] **Step 4: Запустить — pass**

Run: `cd backend && cargo test acme_client_provider_crud`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/db.rs
git commit -m "feat(db): acme_client provider CRUD"
```

---

## Task 5: DB-методы — заказы (CRUD)

**Files:**
- Modify: `backend/src/db.rs`

**Interfaces:**
- Consumes: `AcmeClientOrder`, `TxtRecord`.
- Produces:
  - `async fn insert_acme_client_order(&self, provider_id: i64, domain: String, include_wildcard: bool, order_url: Option<String>, txt_records: &[TxtRecord], expires_at: Option<i64>) -> Result<AcmeClientOrder>`
  - `async fn get_acme_client_order(&self, id: i64) -> Result<AcmeClientOrder>`
  - `async fn get_all_acme_client_orders(&self) -> Result<Vec<AcmeClientOrder>>`
  - `async fn update_acme_client_order_status(&self, id: i64, status: &str, cert_id: Option<i64>, error: Option<String>) -> Result<()>`
  - `async fn delete_acme_client_order(&self, id: i64) -> Result<()>`

- [ ] **Step 1: Написать тест заказов**

В `backend/src/db.rs` `mod tests`:

```rust
#[tokio::test]
async fn acme_client_order_crud() {
    let db = mem_db().await;
    let p = db.insert_acme_client_provider(
        "CA".into(), "https://acme.example/dir".into(), "".into(), None, None,
    ).await.unwrap();
    let txt = vec![TxtRecord { name: "_acme-challenge.example.com".into(), value: "v1".into() }];
    let o = db.insert_acme_client_order(
        p.id, "example.com".into(), true, Some("https://acme.example/order/1".into()), &txt, Some(123),
    ).await.unwrap();
    assert_eq!(o.status, "pending_dns");
    assert_eq!(o.txt_records.len(), 1);
    assert!(o.include_wildcard);
    db.update_acme_client_order_status(o.id, "valid", Some(42), None).await.unwrap();
    let got = db.get_acme_client_order(o.id).await.unwrap();
    assert_eq!(got.status, "valid");
    assert_eq!(got.cert_id, Some(42));
    assert_eq!(db.get_all_acme_client_orders().await.unwrap().len(), 1);
    db.delete_acme_client_order(o.id).await.unwrap();
    assert_eq!(db.get_all_acme_client_orders().await.unwrap().len(), 0);
}
```

- [ ] **Step 2: Запустить — fail**

Run: `cd backend && cargo test acme_client_order_crud`
Expected: ошибка компиляции.

- [ ] **Step 3: Реализовать методы и маппер**

В `impl VaulTLSDB`:

```rust
pub(crate) async fn insert_acme_client_order(
    &self,
    provider_id: i64,
    domain: String,
    include_wildcard: bool,
    order_url: Option<String>,
    txt_records: &[TxtRecord],
    expires_at: Option<i64>,
) -> Result<AcmeClientOrder> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let txt_json = serde_json::to_string(txt_records)?;
    let id = db_do!(self.pool, |conn: &Connection| {
        conn.execute(
            "INSERT INTO acme_client_orders (provider_id, domain, include_wildcard, status, order_url, txt_records, created_on, expires_at) \
             VALUES (?1, ?2, ?3, 'pending_dns', ?4, ?5, ?6, ?7)",
            params![provider_id, domain, include_wildcard, order_url, txt_json, now, expires_at],
        )?;
        Ok::<i64, anyhow::Error>(conn.last_insert_rowid())
    })?;
    self.get_acme_client_order(id).await
}

pub(crate) async fn get_acme_client_order(&self, id: i64) -> Result<AcmeClientOrder> {
    db_do!(self.pool, |conn: &Connection| {
        Ok(conn.query_row(
            "SELECT id, provider_id, domain, include_wildcard, status, order_url, txt_records, cert_id, error, created_on, expires_at \
             FROM acme_client_orders WHERE id = ?1",
            params![id],
            acme_client_order_from_row,
        )?)
    })
}

pub(crate) async fn get_all_acme_client_orders(&self) -> Result<Vec<AcmeClientOrder>> {
    db_do!(self.pool, |conn: &Connection| {
        let mut stmt = conn.prepare(
            "SELECT id, provider_id, domain, include_wildcard, status, order_url, txt_records, cert_id, error, created_on, expires_at \
             FROM acme_client_orders ORDER BY id DESC",
        )?;
        let rows = stmt.query([])?;
        Ok(rows.mapped(acme_client_order_from_row).collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

pub(crate) async fn update_acme_client_order_status(
    &self,
    id: i64,
    status: &str,
    cert_id: Option<i64>,
    error: Option<String>,
) -> Result<()> {
    let status = status.to_string();
    db_do!(self.pool, |conn: &Connection| {
        conn.execute(
            "UPDATE acme_client_orders SET status = ?1, cert_id = COALESCE(?2, cert_id), error = ?3 WHERE id = ?4",
            params![status, cert_id, error, id],
        )?;
        Ok::<(), anyhow::Error>(())
    })
}

pub(crate) async fn delete_acme_client_order(&self, id: i64) -> Result<()> {
    db_do!(self.pool, |conn: &Connection| {
        conn.execute("DELETE FROM acme_client_orders WHERE id = ?1", params![id])?;
        Ok::<(), anyhow::Error>(())
    })
}
```

Маппер:

```rust
fn acme_client_order_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AcmeClientOrder> {
    let txt_json: String = row.get(6)?;
    let txt_records: Vec<TxtRecord> = serde_json::from_str(&txt_json).unwrap_or_default();
    Ok(AcmeClientOrder {
        id: row.get(0)?,
        provider_id: row.get(1)?,
        domain: row.get(2)?,
        include_wildcard: row.get::<_, i64>(3)? != 0,
        status: row.get(4)?,
        order_url: row.get(5)?,
        txt_records,
        cert_id: row.get(7)?,
        error: row.get(8)?,
        created_on: row.get(9)?,
        expires_at: row.get(10)?,
    })
}
```

- [ ] **Step 4: Запустить тесты (вкл. миграционный из Task 2)**

Run: `cd backend && cargo test acme_client_order_crud && cargo test migration_13`
Expected: PASS оба.

- [ ] **Step 5: Commit**

```bash
git add backend/src/db.rs
git commit -m "feat(db): acme_client order CRUD"
```

---

## Task 6: Общий DNS-helper для предпроверки TXT

**Files:**
- Create: `backend/src/dns_check.rs`
- Modify: `backend/src/lib.rs` (`mod dns_check;`)
- Modify: `backend/src/acme/routes.rs` (переиспользовать)

**Interfaces:**
- Produces: `async fn txt_record_present(domain: &str, expected_value: &str, resolver_addr: Option<&str>) -> bool` — резолвит `_acme-challenge.<domain>` через `hickory-resolver` и проверяет наличие `expected_value` среди TXT. `resolver_addr = None` → системный резолвер.

- [ ] **Step 1: Написать тест чистой части (формирование имени)**

Логику резолва против сети не тестируем; выносим имя записи в чистую функцию. В `backend/src/dns_check.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::challenge_record_name;
    #[test]
    fn builds_acme_challenge_name() {
        assert_eq!(challenge_record_name("example.com"), "_acme-challenge.example.com.");
        assert_eq!(challenge_record_name("sub.example.com"), "_acme-challenge.sub.example.com.");
    }
}
```

- [ ] **Step 2: Запустить — fail**

Run: `cd backend && cargo test dns_check`
Expected: ошибка компиляции.

- [ ] **Step 3: Реализовать helper**

Перенести/обобщить логику из `acme/routes.rs::validate_dns01` (строки ~188–230, lookup `_acme-challenge.{domain}.` через hickory). `backend/src/dns_check.rs`:

```rust
use hickory_resolver::TokioResolver;
use tracing::{error, debug};

pub(crate) fn challenge_record_name(domain: &str) -> String {
    format!("_acme-challenge.{}.", domain.trim_end_matches('.'))
}

/// Проверяет, что среди TXT для _acme-challenge.<domain> есть expected_value.
/// resolver_addr = None → системный резолвер.
pub(crate) async fn txt_record_present(domain: &str, expected_value: &str, _resolver_addr: Option<&str>) -> bool {
    let name = challenge_record_name(domain);
    // Системный резолвер; адрес кастомного резолвера интегрировать по образцу acme/routes.rs при необходимости.
    let resolver = match TokioResolver::builder_tokio() {
        Ok(b) => b.build(),
        Err(e) => { error!(error=%e, "resolver build failed"); return false; }
    };
    match resolver.txt_lookup(name.clone()).await {
        Ok(lookup) => {
            let found = lookup.iter().any(|txt| {
                txt.iter().any(|chunk| String::from_utf8_lossy(chunk) == expected_value)
            });
            if !found {
                debug!(domain=domain, expected=expected_value, "TXT not yet visible");
            }
            found
        }
        Err(e) => { debug!(domain=domain, error=%e, "TXT lookup failed"); false }
    }
}
```

> Примечание для реализатора: точные типы `hickory-resolver` 0.26 сверить с уже работающим кодом в `acme/routes.rs` (там тот же крейт). Если builder/lookup API отличается — скопировать рабочий вызов оттуда дословно.

В `backend/src/lib.rs`: `mod dns_check;`. В `acme/routes.rs::validate_dns01` заменить тело DNS-проверки на вызов `crate::dns_check::txt_record_present(...)`, сохранив существующую сигнатуру/поведение (DoH-ветку не трогать).

- [ ] **Step 4: Запустить тесты — pass + регрессия ACME-сервера**

Run: `cd backend && cargo test dns_check && cargo test acme`
Expected: PASS; существующие ACME-серверные тесты не сломаны.

- [ ] **Step 5: Commit**

```bash
git add backend/src/dns_check.rs backend/src/lib.rs backend/src/acme/routes.rs
git commit -m "refactor(dns): extract reusable TXT precheck helper"
```

---

## Task 7: ACME-клиент — идентификаторы заказа (чистая функция)

**Files:**
- Modify: `backend/src/acme_client/client.rs`

**Interfaces:**
- Produces: `fn order_identifiers(domain: &str, include_wildcard: bool) -> Vec<String>` — возвращает `["example.com"]` или `["example.com", "*.example.com"]`.

- [ ] **Step 1: Тест**

В `backend/src/acme_client/client.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::order_identifiers;
    #[test]
    fn single_domain() {
        assert_eq!(order_identifiers("example.com", false), vec!["example.com".to_string()]);
    }
    #[test]
    fn domain_with_wildcard() {
        assert_eq!(
            order_identifiers("example.com", true),
            vec!["example.com".to_string(), "*.example.com".to_string()]
        );
    }
}
```

- [ ] **Step 2: Запустить — fail**

Run: `cd backend && cargo test acme_client::client`
Expected: ошибка компиляции.

- [ ] **Step 3: Реализовать**

В `backend/src/acme_client/client.rs` (заменить placeholder):

```rust
pub(crate) fn order_identifiers(domain: &str, include_wildcard: bool) -> Vec<String> {
    let base = domain.trim().trim_end_matches('.').to_string();
    if include_wildcard {
        vec![base.clone(), format!("*.{base}")]
    } else {
        vec![base]
    }
}
```

- [ ] **Step 4: Запустить — pass**

Run: `cd backend && cargo test acme_client::client`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/acme_client/client.rs
git commit -m "feat(acme-client): order identifier helper"
```

---

## Task 8: ACME-клиент — фаза 1 (создать заказ, вернуть TXT)

**Files:**
- Modify: `backend/src/acme_client/client.rs`

**Interfaces:**
- Consumes: `AcmeClientProvider`, `TxtRecord`, `order_identifiers`, `instant_acme`.
- Produces:
  - `struct CreatedOrder { order_url: String, txt_records: Vec<TxtRecord>, account_credentials: Option<String>, expires_at: Option<i64> }`
  - `async fn create_order(provider: &AcmeClientProvider, domain: &str, include_wildcard: bool) -> anyhow::Result<CreatedOrder>` — регистрирует/восстанавливает аккаунт, создаёт заказ, собирает dns-01 значения. **`set_ready` НЕ вызывает.** Если аккаунт был зарегистрирован впервые — возвращает `account_credentials` (Some) для сохранения.

- [ ] **Step 1: Реализовать (без unit-теста против сети)**

> Это интеграция с внешним ACME-сервером — автотест против сети не пишем (проверка вручную через LE staging в Task 11). Код пишем сразу, корректность типов проверяем компиляцией.

В `backend/src/acme_client/client.rs` добавить:

```rust
use std::sync::Arc;
use anyhow::{anyhow, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, CryptoProvider, DefaultClient,
    ExternalAccountKey, Identifier, NewAccount, NewOrder,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crate::acme_client::types::{AcmeClientProvider, TxtRecord};

pub(crate) struct CreatedOrder {
    pub order_url: String,
    pub txt_records: Vec<TxtRecord>,
    pub account_credentials: Option<String>,
    pub expires_at: Option<i64>,
}

fn http_client() -> Result<Box<DefaultClient>> {
    let rustls_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Ok(Box::new(DefaultClient::new(rustls_provider)?))
}

/// Восстанавливает аккаунт из сохранённых credentials или регистрирует новый.
/// Возвращает (account, Some(creds_json) если только что создан).
async fn account_for(provider: &AcmeClientProvider) -> Result<(Account, Option<String>)> {
    let crypto = CryptoProvider::aws_lc_rs();
    let builder = Account::builder(http_client()?, crypto.clone())?;

    if let Some(creds_json) = &provider.account_credentials {
        let creds: AccountCredentials = serde_json::from_str(creds_json)?;
        let account = builder.from_credentials(creds).await?;
        return Ok((account, None));
    }

    // Первая регистрация
    let contact = format!("mailto:{}", provider.account_email);
    let new_account = NewAccount {
        contact: &[contact.as_str()],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let eab = match (&provider.eab_kid, &provider.eab_hmac_key) {
        (Some(kid), Some(key_bytes)) => {
            let key = crypto.hmac.load_key(key_bytes);
            Some(ExternalAccountKey::new(kid.clone(), key))
        }
        _ => None,
    };
    let (account, creds) = builder
        .create(&new_account, provider.directory_url.clone(), eab.as_ref())
        .await?;
    let creds_json = serde_json::to_string(&creds)?;
    Ok((account, Some(creds_json)))
}

pub(crate) async fn create_order(
    provider: &AcmeClientProvider,
    domain: &str,
    include_wildcard: bool,
) -> Result<CreatedOrder> {
    let (account, new_creds) = account_for(provider).await?;

    let ids: Vec<Identifier> = order_identifiers(domain, include_wildcard)
        .into_iter()
        .map(Identifier::Dns)
        .collect();
    let mut order = account.new_order(&NewOrder::new(&ids)).await?;

    let order_url = order.url().to_string();

    let mut txt_records = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        let mut challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("dns-01 challenge not offered for authorization"))?;
        let value = challenge.key_authorization()?.dns_value();
        txt_records.push(TxtRecord {
            name: format!("_acme-challenge.{}", domain.trim_end_matches('.')),
            value,
        });
        // set_ready НЕ вызываем — ждём ручного ввода в DNS.
    }

    Ok(CreatedOrder {
        order_url,
        txt_records,
        account_credentials: new_creds,
        expires_at: None, // при необходимости заполнить из order metadata
    })
}
```

> Примечание реализатору: методы `order.url()`, `authz.challenge`, `key_authorization().dns_value()`, `builder.create/from_credentials`, `crypto.hmac.load_key` сверить с реальной сигнатурой установленной версии `instant-acme` (см. `cargo doc -p instant-acme --open`). Логика и порядок вызовов соответствуют quick-start крейта. `URL_SAFE_NO_PAD` оставлен для возможного декода EAB ключа на уровне роутов (Task 10), если ключ приходит base64url.

- [ ] **Step 2: Проверить компиляцию**

Run: `cd backend && cargo build`
Expected: сборка проходит (правки сигнатур по примечанию при необходимости).

- [ ] **Step 3: Commit**

```bash
git add backend/src/acme_client/client.rs
git commit -m "feat(acme-client): phase 1 — create order and collect dns-01 TXT"
```

---

## Task 9: ACME-клиент — фаза 2 (предпроверка + выпуск)

**Files:**
- Modify: `backend/src/acme_client/client.rs`

**Interfaces:**
- Consumes: `account_for`, `dns_check::txt_record_present`, `instant_acme::RetryPolicy`.
- Produces:
  - `struct IssuedCert { certificate_pem: String, private_key_pem: String }`
  - `async fn issue_order(provider: &AcmeClientProvider, order_url: &str, domain: &str, txt_records: &[TxtRecord]) -> Result<IssuedCert>` — предпроверяет все TXT резолвером (ошибка, если хоть одной нет), восстанавливает заказ, `set_ready` по challenge, `poll_ready`, `finalize`, `poll_certificate`.

- [ ] **Step 1: Реализовать**

В `backend/src/acme_client/client.rs` добавить:

```rust
use instant_acme::RetryPolicy;

pub(crate) struct IssuedCert {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

pub(crate) async fn issue_order(
    provider: &AcmeClientProvider,
    order_url: &str,
    domain: &str,
    txt_records: &[TxtRecord],
) -> Result<IssuedCert> {
    // 1. Предпроверка DNS — бережём rate-limit ACME.
    for rec in txt_records {
        if !crate::dns_check::txt_record_present(domain, &rec.value, None).await {
            return Err(anyhow!(
                "TXT-запись для _acme-challenge.{domain} ещё не видна в DNS (значение {}). Проверьте зону bind9 и попробуйте позже.",
                rec.value
            ));
        }
    }

    // 2. Восстановить аккаунт и заказ.
    let (account, _creds) = account_for(provider).await?;
    let mut order = account.order(order_url.to_string()).await?;

    // 3. set_ready по каждой dns-01 авторизации.
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
            challenge.set_ready().await?;
        }
    }

    // 4. Дождаться валидации, финализировать, забрать сертификат.
    let _ = order.poll_ready(&RetryPolicy::default()).await?;
    let private_key_pem = order.finalize().await?;
    let certificate_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    Ok(IssuedCert { certificate_pem, private_key_pem })
}
```

> Примечание: `finalize()` в актуальном API сам генерирует ключ и возвращает PEM приватного ключа; `poll_certificate` возвращает PEM-цепочку. Сверить возвращаемые типы (String vs форма) с `cargo doc` и привести к `String`.

- [ ] **Step 2: Проверить компиляцию**

Run: `cd backend && cargo build`
Expected: сборка проходит.

- [ ] **Step 3: Commit**

```bash
git add backend/src/acme_client/client.rs
git commit -m "feat(acme-client): phase 2 — precheck DNS and finalize issuance"
```

---

## Task 10: HTTP-маршруты — провайдеры

**Files:**
- Modify: `backend/src/acme_client/routes.rs`

**Interfaces:**
- Consumes: db-методы провайдеров (Task 4), DTO (Task 3).
- Produces: маршруты `get_acme_client_providers`, `create_acme_client_provider`, `delete_acme_client_provider`.

- [ ] **Step 1: Реализовать маршруты**

`backend/src/acme_client/routes.rs`:

```rust
use rocket::{delete, get, post, State};
use rocket::serde::json::Json;
use rocket_okapi::openapi;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crate::auth::session_auth::AuthenticatedPrivileged;
use crate::data::error::ApiError;
use crate::data::objects::AppState;
use crate::acme_client::types::{AcmeClientProvider, CreateProviderRequest};

#[openapi(tag = "ACME Client")]
#[get("/acme-client/providers")]
pub async fn get_acme_client_providers(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
) -> Result<Json<Vec<AcmeClientProvider>>, ApiError> {
    Ok(Json(state.db.get_all_acme_client_providers().await?))
}

#[openapi(tag = "ACME Client")]
#[post("/acme-client/providers", format = "json", data = "<req>")]
pub async fn create_acme_client_provider(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    req: Json<CreateProviderRequest>,
) -> Result<Json<AcmeClientProvider>, ApiError> {
    let eab_hmac_key = match &req.eab_hmac_key {
        Some(b64) => Some(URL_SAFE_NO_PAD.decode(b64).map_err(|_| ApiError::Other("invalid eab_hmac_key".into()))?),
        None => None,
    };
    let provider = state.db.insert_acme_client_provider(
        req.name.clone(),
        req.directory_url.clone(),
        req.account_email.clone(),
        req.eab_kid.clone(),
        eab_hmac_key,
    ).await?;
    Ok(Json(provider))
}

#[openapi(tag = "ACME Client")]
#[delete("/acme-client/providers/<id>")]
pub async fn delete_acme_client_provider(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
) -> Result<(), ApiError> {
    state.db.delete_acme_client_provider(id).await?;
    Ok(())
}
```

> Сверить вариант `ApiError::Other(String)` с реальным enum в `backend/src/data/error.rs`; если конструктор иной — использовать подходящий (как в существующих роутах).

- [ ] **Step 2: Компиляция**

Run: `cd backend && cargo build`
Expected: проходит (маршруты ещё не зарегистрированы — это Task 11).

- [ ] **Step 3: Commit**

```bash
git add backend/src/acme_client/routes.rs
git commit -m "feat(acme-client): provider HTTP routes"
```

---

## Task 11: HTTP-маршруты — заказы + регистрация в lib.rs

**Files:**
- Modify: `backend/src/acme_client/routes.rs`
- Modify: `backend/src/lib.rs`

**Interfaces:**
- Consumes: db-методы заказов (Task 5), `client::create_order`/`issue_order` (Task 8–9).
- Produces: маршруты `get_acme_client_orders`, `create_acme_client_order` (фаза 1), `issue_acme_client_order` (фаза 2), `delete_acme_client_order`; все зарегистрированы.

- [ ] **Step 1: Реализовать маршруты заказов**

Добавить в `backend/src/acme_client/routes.rs`:

```rust
use crate::acme_client::types::{AcmeClientOrder, CreateOrderRequest, CreateOrderResponse};
use crate::acme_client::client;

#[openapi(tag = "ACME Client")]
#[get("/acme-client/orders")]
pub async fn get_acme_client_orders(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
) -> Result<Json<Vec<AcmeClientOrder>>, ApiError> {
    Ok(Json(state.db.get_all_acme_client_orders().await?))
}

#[openapi(tag = "ACME Client")]
#[post("/acme-client/orders", format = "json", data = "<req>")]
pub async fn create_acme_client_order(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    req: Json<CreateOrderRequest>,
) -> Result<Json<CreateOrderResponse>, ApiError> {
    let provider = state.db.get_acme_client_provider(req.provider_id).await?;
    let created = client::create_order(&provider, &req.domain, req.include_wildcard)
        .await
        .map_err(|e| ApiError::Other(e.to_string()))?;
    if let Some(creds) = created.account_credentials {
        state.db.update_acme_client_provider_credentials(provider.id, creds).await?;
    }
    let order = state.db.insert_acme_client_order(
        provider.id,
        req.domain.clone(),
        req.include_wildcard,
        Some(created.order_url),
        &created.txt_records,
        created.expires_at,
    ).await?;
    Ok(Json(CreateOrderResponse { order_id: order.id, txt_records: order.txt_records }))
}

#[openapi(tag = "ACME Client")]
#[post("/acme-client/orders/<id>/issue")]
pub async fn issue_acme_client_order(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
) -> Result<Json<AcmeClientOrder>, ApiError> {
    let order = state.db.get_acme_client_order(id).await?;
    let provider = state.db.get_acme_client_provider(order.provider_id).await?;
    let order_url = order.order_url.clone()
        .ok_or_else(|| ApiError::Other("order has no URL".into()))?;

    match client::issue_order(&provider, &order_url, &order.domain, &order.txt_records).await {
        Ok(issued) => {
            // Сохранить выпущенный сертификат в user_certificates как внешний ACME-серт.
            let cert_id = state.db.insert_acme_client_certificate(
                &order.domain,
                issued.certificate_pem.into_bytes(),
                issued.private_key_pem.into_bytes(),
                provider.id,
            ).await.map_err(|e| ApiError::Other(e.to_string()))?;
            state.db.update_acme_client_order_status(id, "valid", Some(cert_id), None).await?;
        }
        Err(e) => {
            state.db.update_acme_client_order_status(id, "failed", None, Some(e.to_string())).await?;
            return Err(ApiError::Other(e.to_string()));
        }
    }
    Ok(Json(state.db.get_acme_client_order(id).await?))
}

#[openapi(tag = "ACME Client")]
#[delete("/acme-client/orders/<id>")]
pub async fn delete_acme_client_order(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
) -> Result<(), ApiError> {
    state.db.delete_acme_client_order(id).await?;
    Ok(())
}
```

- [ ] **Step 2: Добавить db-метод сохранения внешнего сертификата**

В `backend/src/db.rs` добавить метод, который пишет строку в `user_certificates` с `ca_id = NULL` и `acme_provider_id = provider`. Сверить РЕАЛЬНУЮ схему `user_certificates` (колонки name/cert/key/created_on/valid_until/user_id/certificate_type) с существующим методом вставки сертификата (`grep -n "INSERT INTO user_certificates" backend/src/db.rs`) и повторить его форму, добавив `acme_provider_id`. Скелет:

```rust
pub(crate) async fn insert_acme_client_certificate(
    &self,
    domain: &str,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    provider_id: i64,
) -> Result<i64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    // valid_until извлечь из сертификата при наличии хелпера; иначе now + 90 дней.
    let valid_until = now + 90 * 24 * 60 * 60 * 1000;
    let name = crate::data::objects::Name::from(domain);
    let id = db_do!(self.pool, |conn: &Connection| {
        conn.execute(
            // ВНИМАНИЕ: список колонок привести в соответствие реальной схеме user_certificates.
            "INSERT INTO user_certificates (name, certificate, key, created_on, valid_until, user_id, certificate_type, ca_id, acme_provider_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
            params![name, cert_pem, key_pem, now, valid_until, 1_i64, 1_i64, provider_id],
        )?;
        Ok::<i64, anyhow::Error>(conn.last_insert_rowid())
    })?;
    Ok(id)
}
```

> Реализатор ОБЯЗАН сверить имена колонок и тип `certificate_type` с существующей вставкой пользовательского сертификата и привести запрос в точное соответствие (иначе FK/NOT NULL упадут). `user_id` = id админа-владельца (взять из guard на уровне роута и прокинуть параметром, если в схеме NOT NULL).

- [ ] **Step 3: Зарегистрировать маршруты в lib.rs**

В `backend/src/lib.rs` в КАЖДОМ из трёх блоков `openapi_get_routes![ ... ]` (по образцу того, где перечислены `get_acme_orders, create_acme_account, ...`) добавить:

```rust
                acme_client::routes::get_acme_client_providers,
                acme_client::routes::create_acme_client_provider,
                acme_client::routes::delete_acme_client_provider,
                acme_client::routes::get_acme_client_orders,
                acme_client::routes::create_acme_client_order,
                acme_client::routes::issue_acme_client_order,
                acme_client::routes::delete_acme_client_order,
```

- [ ] **Step 4: Сборка и тесты**

Run: `cd backend && cargo build && cargo test`
Expected: сборка и все тесты проходят.

- [ ] **Step 5: Ручная проверка против LE staging (документируется, не CI)**

Запустить локально, через Scalar (`/api/`) или curl с admin-сессией:
1. `POST /api/acme-client/orders` с `provider_id` = staging-пресет, `domain` = тестовый домен под управлением, `include_wildcard=false`.
2. Внести показанную TXT в bind9, дождаться распространения (`dig TXT _acme-challenge.<domain>`).
3. `POST /api/acme-client/orders/<id>/issue` → ожидать `status=valid` и появление серта в `user_certificates`.
Зафиксировать результат в описании коммита/PR.

- [ ] **Step 6: Commit**

```bash
git add backend/src/acme_client/routes.rs backend/src/db.rs backend/src/lib.rs
git commit -m "feat(acme-client): order routes (create/issue/delete) + registration"
```

---

## Task 12: Напоминание о продлении LE-сертов

**Files:**
- Modify: `backend/src/notification/notifier.rs`

**Interfaces:**
- Consumes: список сертов с `acme_provider_id IS NOT NULL` и близким `valid_until`.
- Produces: отправку напоминания (по существующему механизму уведомлений) о скором истечении внешних ACME-сертов; авто-выпуск НЕ выполняется (dns-01 ручной).

- [ ] **Step 1: Изучить существующий тикер**

Прочитать `backend/src/notification/notifier.rs` (цикл `interval`, выборка `certs` с близким `valid_until`). Определить, где добавить ветку для сертов с `acme_provider_id`.

- [ ] **Step 2: Добавить выборку и напоминание**

В цикле тикера, рядом с обработкой обычных сертов, добавить: для сертов с `acme_provider_id.is_some()` и `valid_until < now + неделя` — отправить уведомление-напоминание (использовать тот же mailer-вызов, что и `CertificateRenewMethod::Notify`), без попытки авто-renew. Логировать `info!("LE cert {} expiring, manual renewal required", ...)`.

> Конкретные имена полей серта (`valid_until`, `acme_provider_id`) и mailer-метод взять из существующего кода файла. Если структура серта в выборке notifier ещё не содержит `acme_provider_id` — расширить соответствующий SELECT/маппер минимально.

- [ ] **Step 3: Сборка и тесты**

Run: `cd backend && cargo build && cargo test`
Expected: проходит.

- [ ] **Step 4: Commit**

```bash
git add backend/src/notification/notifier.rs
git commit -m "feat(notifier): reminder for expiring ACME-client certificates"
```

---

## Task 13: Frontend — типы и API-клиент

**Files:**
- Create: `frontend/src/types/AcmeClient.ts`
- Create: `frontend/src/api/acmeClient.ts`

**Interfaces:**
- Produces: TS-типы `AcmeClientProvider`, `AcmeClientOrder`, `TxtRecord`, `CreateOrderResponse`; функции API `fetchProviders`, `createProvider`, `deleteProvider`, `fetchOrders`, `createOrder`, `issueOrder`, `deleteOrder`.

- [ ] **Step 1: Создать типы**

`frontend/src/types/AcmeClient.ts`:

```ts
export interface TxtRecord {
  name: string
  value: string
}

export interface AcmeClientProvider {
  id: number
  name: string
  directory_url: string
  account_email: string
  eab_kid?: string | null
  created_on: number
}

export interface AcmeClientOrder {
  id: number
  provider_id: number
  domain: string
  include_wildcard: boolean
  status: string
  order_url?: string | null
  txt_records: TxtRecord[]
  cert_id?: number | null
  error?: string | null
  created_on: number
  expires_at?: number | null
}

export interface CreateOrderResponse {
  order_id: number
  txt_records: TxtRecord[]
}

export interface CreateProviderRequest {
  name: string
  directory_url: string
  account_email: string
  eab_kid?: string
  eab_hmac_key?: string
}

export interface CreateOrderRequest {
  provider_id: number
  domain: string
  include_wildcard: boolean
}
```

- [ ] **Step 2: Создать API-клиент**

`frontend/src/api/acmeClient.ts`:

```ts
import ApiClient from '@/api/ApiClient.ts'
import type {
  AcmeClientProvider, AcmeClientOrder, CreateOrderResponse,
  CreateProviderRequest, CreateOrderRequest,
} from '@/types/AcmeClient.ts'

export const fetchProviders = async (): Promise<AcmeClientProvider[]> =>
  ApiClient.get<AcmeClientProvider[]>('/acme-client/providers')

export const createProvider = async (req: CreateProviderRequest): Promise<AcmeClientProvider> =>
  ApiClient.post<AcmeClientProvider>('/acme-client/providers', req)

export const deleteProvider = async (id: number): Promise<void> =>
  ApiClient.delete<void>(`/acme-client/providers/${id}`)

export const fetchOrders = async (): Promise<AcmeClientOrder[]> =>
  ApiClient.get<AcmeClientOrder[]>('/acme-client/orders')

export const createOrder = async (req: CreateOrderRequest): Promise<CreateOrderResponse> =>
  ApiClient.post<CreateOrderResponse>('/acme-client/orders', req)

export const issueOrder = async (id: number): Promise<AcmeClientOrder> =>
  ApiClient.post<AcmeClientOrder>(`/acme-client/orders/${id}/issue`, {})

export const deleteOrder = async (id: number): Promise<void> =>
  ApiClient.delete<void>(`/acme-client/orders/${id}`)
```

> Сверить сигнатуры `ApiClient.get/post/delete` с `frontend/src/api/ApiClient.ts` (число аргументов у `post`). Привести вызовы в точное соответствие.

- [ ] **Step 3: Проверка типов**

Run: `cd frontend && npx vue-tsc --noEmit`
Expected: без ошибок.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/types/AcmeClient.ts frontend/src/api/acmeClient.ts
git commit -m "feat(fe): acme-client types and api client"
```

---

## Task 14: Frontend — Pinia store

**Files:**
- Create: `frontend/src/stores/acmeClient.ts`

**Interfaces:**
- Consumes: api из Task 13.
- Produces: store `useAcmeClientStore` со state `providers`, `orders`, `loading`, `error` и actions `fetchProviders`, `fetchOrders`, `addProvider`, `removeProvider`, `newOrder` (возвращает `CreateOrderResponse`), `issue`, `removeOrder`.

- [ ] **Step 1: Создать store**

`frontend/src/stores/acmeClient.ts` (по образцу `stores/cas.ts`):

```ts
import { defineStore } from 'pinia'
import axios from 'axios'
import type { AcmeClientProvider, AcmeClientOrder, CreateOrderResponse, CreateProviderRequest, CreateOrderRequest } from '@/types/AcmeClient.ts'
import * as api from '@/api/acmeClient.ts'

export const useAcmeClientStore = defineStore('acmeClient', {
  state: () => ({
    providers: [] as AcmeClientProvider[],
    orders: [] as AcmeClientOrder[],
    loading: false,
    error: null as string | null,
  }),
  actions: {
    async fetchProviders() {
      this.error = null
      try { this.providers = await api.fetchProviders() }
      catch (e) { this.error = axios.isAxiosError(e) ? (e.response?.data?.error ?? 'Failed') : 'Failed' }
    },
    async fetchOrders() {
      this.error = null
      try { this.orders = await api.fetchOrders() }
      catch (e) { this.error = axios.isAxiosError(e) ? (e.response?.data?.error ?? 'Failed') : 'Failed' }
    },
    async addProvider(req: CreateProviderRequest) { await api.createProvider(req); await this.fetchProviders() },
    async removeProvider(id: number) { await api.deleteProvider(id); await this.fetchProviders() },
    async newOrder(req: CreateOrderRequest): Promise<CreateOrderResponse> {
      this.loading = true
      try { const res = await api.createOrder(req); await this.fetchOrders(); return res }
      finally { this.loading = false }
    },
    async issue(id: number) {
      this.loading = true
      try { await api.issueOrder(id); await this.fetchOrders() }
      finally { this.loading = false }
    },
    async removeOrder(id: number) { await api.deleteOrder(id); await this.fetchOrders() },
  },
})
```

- [ ] **Step 2: Проверка типов**

Run: `cd frontend && npx vue-tsc --noEmit`
Expected: без ошибок.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/stores/acmeClient.ts
git commit -m "feat(fe): acme-client pinia store"
```

---

## Task 15: Frontend — вкладка «Let's Encrypt»

**Files:**
- Create: `frontend/src/components/AcmeClientTab.vue`

**Interfaces:**
- Consumes: `useAcmeClientStore`, `BaseModal`, PrimeVue `DataTable`/`Column`/`Button`/`Select`/`InputText`/`ToggleSwitch`/`Tag`.
- Produces: компонент с двумя секциями (провайдеры, заказы), мастером создания заказа, экраном показа TXT-записей с копированием, кнопками «Проверить и выпустить» / «Продлить» / «Удалить».

- [ ] **Step 1: Создать компонент**

`frontend/src/components/AcmeClientTab.vue` — по образцу `AcmeTab.vue`/`OverviewTab.vue`. Минимально содержит:
- header с заголовком `$t('le.title')`;
- секция «Провайдеры»: `DataTable` (name, directory_url) + кнопка «Добавить» (модалка `CreateProviderRequest`: name, directory_url, email, опц. eab_kid/eab_hmac_key) + удаление;
- секция «Заказы»: `DataTable` (domain, wildcard, status-`Tag`, created) + кнопка «Новый сертификат»;
- модалка создания заказа: `Select` провайдера, `InputText` домен, `ToggleSwitch` wildcard → по submit вызывает `store.newOrder()` и показывает результат;
- экран/модалка TXT: список `txt_records` (`name`, `value`) с кнопкой копирования (`navigator.clipboard.writeText`) и подсказкой `$t('le.dnsHint')`; кнопка «Проверить и выпустить» → `store.issue(orderId)`;
- для заказов в статусе `valid` — кнопка «Продлить» (создаёт новый заказ тем же провайдером/доменом и снова показывает TXT);
- `onMounted` → `store.fetchProviders()` + `store.fetchOrders()`.

Стили — повторить классы из существующих вкладок (`vt-head`, `vt-table`, `vt-row-actions`, `vt-field`, `vt-switch-field` с `flex-shrink:0` для свитча — как уже исправлено в AcmeTab).

> Это UI-задача без unit-теста; корректность проверяется типизацией и ручным прогоном в Task 16/Validation.

- [ ] **Step 2: Проверка типов**

Run: `cd frontend && npx vue-tsc --noEmit`
Expected: без ошибок.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/AcmeClientTab.vue
git commit -m "feat(fe): Let's Encrypt tab (providers, orders, manual dns-01 wizard)"
```

---

## Task 16: Frontend — роут, меню, локали

**Files:**
- Modify: `frontend/src/router/index.ts`
- Modify: `frontend/src/components/Sidebar.vue`
- Modify: `frontend/src/locales/en.json`, `frontend/src/locales/es.json`

**Interfaces:**
- Produces: маршрут `/letsencrypt` (name `LetsEncrypt`), пункт меню (admin-only), строки локализации `sidebar.letsencrypt` и группа `le.*`.

- [ ] **Step 1: Добавить роут**

В `frontend/src/router/index.ts`: импорт `import AcmeClientTab from '@/components/AcmeClientTab.vue'` и в children `MainLayout` (рядом с `acme`):

```ts
                {
                    path: 'letsencrypt',
                    name: 'LetsEncrypt',
                    component: AcmeClientTab,
                },
```

- [ ] **Step 2: Добавить пункт меню**

В `frontend/src/components/Sidebar.vue` в `items` (admin-only, рядом с `acme`):

```ts
  ...(auth.isAdmin ? [
    { name: 'letsencrypt', to: '/letsencrypt', icon: 'pi pi-verified', label: 'sidebar.letsencrypt' },
  ] : []),
```

- [ ] **Step 3: Добавить локали**

В `en.json` `sidebar` добавить `"letsencrypt": "Let's Encrypt",` и новую группу верхнего уровня:

```json
  "le": {
    "title": "Let's Encrypt",
    "providers": "ACME Providers",
    "orders": "Certificate Orders",
    "newCert": "New Certificate",
    "domain": "Domain",
    "wildcard": "Include wildcard (*.domain)",
    "dnsHint": "Add these TXT records to your bind9 zone, bump the serial and run rndc reload, then click Check & Issue.",
    "checkIssue": "Check & Issue",
    "renew": "Renew",
    "copy": "Copy"
  },
```

В `es.json` — те же ключи с испанскими значениями (`"letsencrypt": "Let's Encrypt"`, `le.title` = `"Let's Encrypt"`, `providers` = `"Proveedores ACME"`, `orders` = `"Pedidos de certificados"`, `newCert` = `"Nuevo certificado"`, `domain` = `"Dominio"`, `wildcard` = `"Incluir comodín (*.dominio)"`, `dnsHint` = `"Añade estos registros TXT a tu zona bind9, sube el serial y ejecuta rndc reload, luego pulsa Comprobar y emitir."`, `checkIssue` = `"Comprobar y emitir"`, `renew` = `"Renovar"`, `copy` = `"Copiar"`). `fr.json` не трогать.

- [ ] **Step 4: Проверка типов**

Run: `cd frontend && npx vue-tsc --noEmit`
Expected: без ошибок.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/router/index.ts frontend/src/components/Sidebar.vue frontend/src/locales/en.json frontend/src/locales/es.json
git commit -m "feat(fe): route, menu item and i18n for Let's Encrypt tab"
```

---

## Task 17: Overview — имя провайдера для LE-сертов

**Files:**
- Modify: `frontend/src/components/OverviewTab.vue`
- Modify: `frontend/src/types/Certificate.ts` (если есть поле сертификата)

**Interfaces:**
- Consumes: поле `acme_provider_id` на сертификате; store провайдеров.
- Produces: колонка «CA Name» показывает имя ACME-провайдера для сертов с `acme_provider_id`, иначе — имя внутреннего CA (как сейчас).

- [ ] **Step 1: Расширить тип сертификата**

В `frontend/src/types/Certificate.ts` добавить `acme_provider_id?: number | null` к интерфейсу сертификата (сверить имя интерфейса).

- [ ] **Step 2: Обновить `caName` в OverviewTab**

В `OverviewTab.vue` подключить `useAcmeClientStore`, в `onMounted` догрузить провайдеров (`acmeClientStore.fetchProviders()`), и в helper `caName` сначала проверять провайдера:

```ts
const caName = (data: Certificate): string => {
  if (data.acme_provider_id != null) {
    const p = acmeClientStore.providers.find(x => x.id === data.acme_provider_id)
    return p ? p.name : `ACME #${data.acme_provider_id}`
  }
  if (data.ca_id == null) return ''
  return caStore.cas.get(data.ca_id)?.name.cn ?? String(data.ca_id)
}
```

И в шаблоне колонки «CA Name» передавать `data` целиком: `{{ caName(data) }}` (вместо `caName(data.ca_id)` — обновить обе таблицы).

> Это меняет сигнатуру `caName` с `(caId)` на `(cert)` — поправить оба места вызова в шаблоне.

- [ ] **Step 3: Проверка типов**

Run: `cd frontend && npx vue-tsc --noEmit`
Expected: без ошибок.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/OverviewTab.vue frontend/src/types/Certificate.ts
git commit -m "feat(fe): show ACME provider name in Overview CA column"
```

---

## Финальная проверка

- [ ] `cd backend && cargo test` — все тесты зелёные
- [ ] `cd backend && cargo build --release` — сборка проходит
- [ ] `cd frontend && npx vue-tsc --noEmit` — типы чистые
- [ ] `cd frontend && npm run build` — фронт собирается
- [ ] Ручной e2e против LE staging: создать заказ → внести TXT в bind9 → выпустить → серт виден и скачивается из Overview с именем провайдера в колонке «CA Name»

---

## Соответствие спеке (self-review)

- §3 instant-acme → Task 1, 8, 9
- §4.1 провайдеры (+seed LE) → Task 2, 4
- §4.2 заказы → Task 2, 5
- §4.3 `acme_provider_id`, `ca_id` NULL → Task 2, 11(step 2), 17
- §5 двухфазный поток + предпроверка → Task 8 (фаза 1), 9 (фаза 2 + dns_check), 11 (роуты)
- §5 продление (кнопка + notifier) → Task 12, 15
- §6 API → Task 10, 11
- §7 UI новая вкладка + Overview → Task 15, 16, 17
- §8 обработка ошибок (rate-limit/предпроверка/failed) → Task 9, 11
- §10 переиспользование (dns_check, notifier, миграции) → Task 6, 12, 2
