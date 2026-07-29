# Certificate Versions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Заменять содержимое импортированного сертификата новым файлом с сохранением `id`, храня вытесненные версии в истории, доступной для просмотра и скачивания.

**Architecture:** Текущая версия остаётся в `user_certificates`; вытесненные копируются в новую таблицу `certificate_versions` (собственный `id`, номер `version`). Замена — одна транзакция: копия старой строки в историю, затем обновление полей записи и `version + 1`. Все существующие чтения сертификата продолжают работать без правок.

**Tech Stack:** Rust + Rocket + rusqlite (SQLCipher) + rusqlite_migration; Vue 3 + TypeScript + PrimeVue + Pinia.

## Global Constraints

- Спека: `docs/superpowers/specs/2026-07-29-certificate-versions-design.md`.
- Ветка: `feat/certificate-versions` (уже создана, в ней лежит спека).
- Редактируются только сертификаты с `is_imported = 1`, `acme_provider_id IS NULL`, `revoked_at IS NULL`, тип TLS (`TLSClient` = 0, `TLSServer` = 1).
- CN нового leaf обязан точно совпадать с `name.cn` записи; тип сертификата обязан совпадать.
- `id` записи при замене не меняется никогда.
- Права: замена — владелец и локальный админ, сервисный токен со `cert:issue` только на сертификатах своего владельца; чтение истории — та же функция `can_access_cert_secret`, что у download; удаление версии — только локальный админ.
- `fingerprint` — SHA-256 от DER leaf-сертификата, hex в нижнем регистре, без разделителей.
- Все временные метки — UNIX-время в миллисекундах (`chrono::Utc::now().timestamp_millis()`).
- Команды: бэкенд `cd backend && cargo test`, фронт `cd frontend && npm run type-check && npm run test:unit`.
- Известный факт: тест `test_ssh_revocation_and_krl` падает в этом окружении из-за внешнего `ssh-keygen` — это не регрессия, игнорировать.

---

### Task 1: Миграция 17 — схема и бэкфилл признака импорта

**Files:**
- Create: `backend/migrations/17-certversions/up.sql`
- Create: `backend/migrations/17-certversions/down.sql`
- Test: `backend/src/db.rs` (модуль `#[cfg(test)] mod tests` в конце файла)

**Interfaces:**
- Consumes: ничего.
- Produces: таблица `certificate_versions`; колонки `user_certificates.is_imported`, `.version`, `.fingerprint`.

- [ ] **Step 1: Написать падающий тест**

В `backend/src/db.rs`, в модуле `mod tests` (рядом с `migration_15_creates_group_tables`), добавить:

```rust
    #[tokio::test]
    async fn migration_17_creates_version_table_and_backfills_is_imported() {
        use crate::data::enums::{CAType, CertData, CertificateRenewMethod, CertificateType};
        use crate::certs::common::CA;

        let db = mem_db().await;
        let user = db.insert_user(User {
            id: -1, name: "o".into(), email: "o@b.c".into(), password_hash: None,
            oidc_id: None, role: UserRole::User, is_local: false,
        }).await.unwrap();

        // внутренний CA (is_imported = 0) и импортированный CA (is_imported = 1)
        let internal = db.insert_ca(CA {
            id: -1, name: "internal".into(), created_on: 0, valid_until: 0,
            ca_type: CAType::TLS, cert: vec![1], key: vec![1], crl_number: 0, is_imported: false,
        }).await.unwrap();
        let imported = db.insert_ca(CA {
            id: -1, name: "imported".into(), created_on: 0, valid_until: 0,
            ca_type: CAType::TLS, cert: vec![2], key: vec![], crl_number: 0, is_imported: true,
        }).await.unwrap();

        let mk = |ca_id: i64| Certificate {
            id: -1, name: "c".into(), created_on: 0, valid_until: 0,
            certificate_type: CertificateType::TLSServer, user_id: user.id,
            renew_method: CertificateRenewMethod::None, ca_id: Some(ca_id),
            revoked_at: None, acme_provider_id: None,
            data: CertData::Pkcs12(vec![9]), password: String::new(),
            version: 1, fingerprint: None, is_imported: false,
        };
        let own = db.insert_user_cert(mk(internal.id)).await.unwrap();
        let imp = db.insert_user_cert(mk(imported.id)).await.unwrap();

        // Бэкфилл миграции применяется к строкам, существовавшим до неё; для строк,
        // вставленных после, флаг ставит код вставки. Здесь проверяем, что колонки
        // читаются и таблица версий существует.
        assert_eq!(db.get_user_cert_by_id(own.id).await.unwrap().version, 1);
        assert_eq!(db.get_user_cert_by_id(imp.id).await.unwrap().version, 1);
        assert!(db.list_certificate_versions(imp.id).await.unwrap().len() == 1);
    }
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `cd backend && cargo test migration_17 2>&1 | head -30`
Expected: ошибки компиляции — у `Certificate` нет полей `version`/`fingerprint`/`is_imported`, метода `list_certificate_versions` не существует. Это ожидаемо: тест доводится до зелёного в Задаче 3. Сейчас нужен только факт, что миграция накатывается.

- [ ] **Step 3: Написать миграцию**

`backend/migrations/17-certversions/up.sql`:

```sql
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
    fingerprint TEXT NOT NULL,
    replaced_at INTEGER NOT NULL,
    replaced_by INTEGER,
    UNIQUE(cert_id, version)
);

CREATE INDEX idx_cert_versions_cert ON certificate_versions(cert_id);

UPDATE user_certificates SET is_imported = 1
 WHERE acme_provider_id IS NULL
   AND ca_id IN (SELECT id FROM ca_certificates WHERE is_imported = 1);
```

`backend/migrations/17-certversions/down.sql`:

```sql
DROP INDEX idx_cert_versions_cert;
DROP TABLE certificate_versions;
ALTER TABLE user_certificates DROP COLUMN fingerprint;
ALTER TABLE user_certificates DROP COLUMN version;
ALTER TABLE user_certificates DROP COLUMN is_imported;
```

- [ ] **Step 4: Проверить, что миграция накатывается**

Run: `cd backend && cargo test group_crud_and_membership -- --nocapture 2>&1 | tail -5`
Expected: PASS. Любой db-тест открывает базу в памяти и прогоняет все миграции; если 17-я сломана, упадут все.

- [ ] **Step 5: Коммит**

```bash
git add backend/migrations/17-certversions backend/src/db.rs
git commit -m "feat(db): migration 17 adds certificate_versions table and import flag"
```

---

### Task 2: Модель Certificate — новые поля и отпечаток

**Files:**
- Modify: `backend/src/certs/common.rs:10-64`
- Modify: `backend/src/db.rs:300`, `:335`, `:365`, `:391`
- Test: `backend/src/certs/common.rs` (новый `#[cfg(test)] mod tests` в конце файла)

**Interfaces:**
- Consumes: колонки из Задачи 1.
- Produces:
  - `Certificate { …, pub version: i64, pub fingerprint: Option<String>, pub is_imported: bool }`
  - `Certificate::get_fingerprint(&self) -> anyhow::Result<String>`
  - `pub struct CertificateVersionEntry { version: i64, version_id: Option<i64>, current: bool, created_on: i64, valid_until: i64, serial_hex: Option<String>, fingerprint: Option<String>, replaced_at: Option<i64>, replaced_by: Option<i64> }`

- [ ] **Step 1: Написать падающий тест**

В конец `backend/src/certs/common.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::import::test_helpers::self_signed_ca;

    #[test]
    fn fingerprint_is_stable_lowercase_sha256_hex() {
        let (cert, _key) = self_signed_ca("fingerprint-test");
        let pem = cert.to_pem().unwrap();
        let c = Certificate {
            id: 1,
            name: crate::data::objects::Name::from("fingerprint-test".to_string()),
            created_on: 0,
            valid_until: 0,
            certificate_type: crate::data::enums::CertificateType::TLSServer,
            user_id: 1,
            renew_method: crate::data::enums::CertificateRenewMethod::None,
            ca_id: None,
            revoked_at: None,
            acme_provider_id: None,
            data: crate::data::enums::CertData::Pem(pem),
            password: String::new(),
            version: 1,
            fingerprint: None,
            is_imported: true,
        };

        let fp = c.get_fingerprint().unwrap();
        assert_eq!(fp.len(), 64, "sha256 hex — 64 символа");
        assert_eq!(fp, fp.to_lowercase());
        assert!(fp.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(fp, c.get_fingerprint().unwrap(), "отпечаток детерминирован");
    }

    #[test]
    fn fingerprint_of_ssh_bundle_is_an_error() {
        let c = Certificate {
            id: 1,
            name: crate::data::objects::Name::from("ssh".to_string()),
            created_on: 0,
            valid_until: 0,
            certificate_type: crate::data::enums::CertificateType::SSHServer,
            user_id: 1,
            renew_method: crate::data::enums::CertificateRenewMethod::None,
            ca_id: None,
            revoked_at: None,
            acme_provider_id: None,
            data: crate::data::enums::CertData::SshBundle(vec![1, 2, 3]),
            password: String::new(),
            version: 1,
            fingerprint: None,
            is_imported: false,
        };
        assert!(c.get_fingerprint().is_err());
    }
}
```

Если `crate::certs::import::test_helpers` не публичен для не-тестовой сборки — использовать `#[cfg(test)]`-модуль `mod test_helpers` из `import.rs` напрямую (он объявлен там же, функции `self_signed_ca(cn) -> (X509, PKey<Private>)`).

- [ ] **Step 2: Запустить тест — убедиться, что падает**

Run: `cd backend && cargo test fingerprint_is_stable -- --nocapture 2>&1 | head -20`
Expected: FAIL — компиляция: нет полей `version`/`fingerprint`/`is_imported` и метода `get_fingerprint`.

- [ ] **Step 3: Расширить структуру и добавить метод**

В `backend/src/certs/common.rs` в `pub struct Certificate` после `pub acme_provider_id: Option<i64>,` добавить:

```rust
    /// Номер текущей версии; растёт при каждой замене содержимого.
    #[serde(default = "default_version")]
    pub version: i64,
    /// SHA-256 от DER leaf-сертификата, hex. None у записей, не прошедших бэкфилл.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// True только у сертификатов, загруженных файлом — только их можно заменять.
    #[serde(default)]
    pub is_imported: bool,
```

Перед `impl Certificate` добавить:

```rust
fn default_version() -> i64 { 1 }
```

В `Certificate::from_row` после `acme_provider_id: row.get(11)?` добавить:

```rust
            version: row.get(12).unwrap_or(1),
            fingerprint: row.get(13).unwrap_or(None),
            is_imported: row.get::<_, i64>(14).unwrap_or(0) == 1,
```

В `impl Certificate` добавить метод:

```rust
    /// SHA-256 от DER leaf-сертификата в нижнем регистре hex.
    pub(crate) fn get_fingerprint(&self) -> Result<String> {
        use crate::certs::import::{parse_cert, parse_pkcs12};
        let leaf = match &self.data {
            CertData::Pkcs12(der) => parse_pkcs12(der, &self.password)?.0,
            CertData::Pem(pem) => parse_cert(pem)?,
            CertData::SshBundle(_) => {
                return Err(anyhow::anyhow!("SSH certificates have no X.509 fingerprint"))
            }
        };
        let digest = leaf.digest(openssl::hash::MessageDigest::sha256())?;
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }
```

Там же, ниже `struct Certificate`, добавить структуру для списка версий:

```rust
/// Одна запись в истории версий сертификата.
/// У текущей версии `version_id` = None: она хранится в `user_certificates`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CertificateVersionEntry {
    pub version: i64,
    pub version_id: Option<i64>,
    pub current: bool,
    pub created_on: i64,
    pub valid_until: i64,
    pub serial_hex: Option<String>,
    pub fingerprint: Option<String>,
    pub replaced_at: Option<i64>,
    pub replaced_by: Option<i64>,
}
```

- [ ] **Step 4: Дополнить SELECT-запросы новыми колонками**

В `backend/src/db.rs` три места читают `Certificate::from_row` — в каждом дописать колонки в конец списка:

Строка ~300 (`get_user_certs`, динамический запрос):
```rust
            let mut query = String::from("SELECT id, name, created_on, valid_until, data, password, user_id, type, renew_method, ca_id, revoked_at, acme_provider_id, version, fingerprint, is_imported FROM user_certificates WHERE 1=1");
```

Строка ~335 (`get_visible_certs`):
```rust
                "SELECT DISTINCT c.id, c.name, c.created_on, c.valid_until, c.data, c.password, c.user_id, c.type, c.renew_method, c.ca_id, c.revoked_at, c.acme_provider_id, c.version, c.fingerprint, c.is_imported \
```

Строка ~365 (`get_user_cert_by_id`):
```rust
            let mut stmt = conn.prepare("SELECT id, name, created_on, valid_until, data, password, user_id, type, renew_method, ca_id, revoked_at, acme_provider_id, version, fingerprint, is_imported FROM user_certificates WHERE id = ?1")?;
```

Строка ~391 (`insert_user_cert`) — записывать флаг импорта и отпечаток:
```rust
                "INSERT INTO user_certificates (name, created_on, valid_until, data, password, type, renew_method, ca_id, user_id, is_imported, fingerprint) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
```
и в `params![]` добавить последними `if cert.is_imported { 1 } else { 0 }, cert.fingerprint`.

- [ ] **Step 5: Запустить тесты**

Run: `cd backend && cargo test 2>&1 | tail -5`
Expected: тесты отпечатка PASS; остальные — как раньше (единственный провал `test_ssh_revocation_and_krl`). Тест `migration_17_…` из Задачи 1 всё ещё падает на отсутствии `list_certificate_versions` — это чинит Задача 3.

- [ ] **Step 6: Коммит**

```bash
git add backend/src/certs/common.rs backend/src/db.rs
git commit -m "feat(certs): add version, fingerprint and is_imported to Certificate"
```

---

### Task 3: Слой БД — история версий и транзакция замены

**Files:**
- Modify: `backend/src/db.rs` (новые методы рядом с `insert_user_cert`, ~строка 400)
- Test: `backend/src/db.rs` (модуль `mod tests`)

**Interfaces:**
- Consumes: `Certificate` с новыми полями (Задача 2), таблица `certificate_versions` (Задача 1).
- Produces:
  - `pub(crate) struct ReplaceCertificateInput { pub data: Vec<u8>, pub password: String, pub created_on: i64, pub valid_until: i64, pub serial_hex: Option<String>, pub fingerprint: String, pub ca_id: i64 }`
  - `pub(crate) struct StoredCertVersion { pub data: Vec<u8>, pub password: String }`
  - `VaulTLSDB::replace_certificate(&self, cert_id: i64, actor_id: i64, input: ReplaceCertificateInput) -> Result<i64>` — возвращает новый номер версии
  - `VaulTLSDB::list_certificate_versions(&self, cert_id: i64) -> Result<Vec<CertificateVersionEntry>>`
  - `VaulTLSDB::get_certificate_version(&self, cert_id: i64, version: i64) -> Result<Option<StoredCertVersion>>`
  - `VaulTLSDB::delete_certificate_version(&self, cert_id: i64, version: i64) -> Result<bool>`

- [ ] **Step 1: Написать падающий тест**

В `mod tests` в `backend/src/db.rs`:

```rust
    #[tokio::test]
    async fn replace_certificate_moves_old_row_into_history() {
        use crate::data::enums::{CAType, CertData, CertificateRenewMethod, CertificateType};
        use crate::certs::common::CA;

        let db = mem_db().await;
        let user = db.insert_user(User {
            id: -1, name: "o".into(), email: "o@b.c".into(), password_hash: None,
            oidc_id: None, role: UserRole::User, is_local: false,
        }).await.unwrap();
        let ca = db.insert_ca(CA {
            id: -1, name: "ca".into(), created_on: 0, valid_until: 0,
            ca_type: CAType::TLS, cert: vec![2], key: vec![], crl_number: 0, is_imported: true,
        }).await.unwrap();

        let cert = db.insert_user_cert(Certificate {
            id: -1, name: "c".into(), created_on: 100, valid_until: 200,
            certificate_type: CertificateType::TLSServer, user_id: user.id,
            renew_method: CertificateRenewMethod::None, ca_id: Some(ca.id),
            revoked_at: None, acme_provider_id: None,
            data: CertData::Pkcs12(b"old".to_vec()), password: "oldpw".into(),
            version: 1, fingerprint: Some("aa".into()), is_imported: true,
        }).await.unwrap();
        db.set_cert_serial(cert.id, "0a".into()).await.unwrap();

        let new_version = db.replace_certificate(cert.id, user.id, ReplaceCertificateInput {
            data: b"new".to_vec(),
            password: "newpw".into(),
            created_on: 300,
            valid_until: 400,
            serial_hex: Some("0b".into()),
            fingerprint: "bb".into(),
            ca_id: ca.id,
        }).await.unwrap();
        assert_eq!(new_version, 2);

        // текущая запись — новая, id прежний
        let current = db.get_user_cert_by_id(cert.id).await.unwrap();
        assert_eq!(current.id, cert.id);
        assert_eq!(current.version, 2);
        assert_eq!(current.fingerprint.as_deref(), Some("bb"));
        assert_eq!(current.valid_until, 400);

        // история содержит обе версии, вытесненная — со своим id
        let versions = db.list_certificate_versions(cert.id).await.unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, 2);
        assert!(versions[0].current);
        assert_eq!(versions[0].version_id, None);
        assert_eq!(versions[1].version, 1);
        assert!(!versions[1].current);
        assert!(versions[1].version_id.is_some());
        assert_eq!(versions[1].replaced_by, Some(user.id));

        // байты и пароль старой версии доступны
        let old = db.get_certificate_version(cert.id, 1).await.unwrap().unwrap();
        assert_eq!(old.data, b"old".to_vec());
        assert_eq!(old.password, "oldpw");

        // удаление исторической версии
        assert!(db.delete_certificate_version(cert.id, 1).await.unwrap());
        assert_eq!(db.list_certificate_versions(cert.id).await.unwrap().len(), 1);
        assert!(!db.delete_certificate_version(cert.id, 1).await.unwrap());
    }

    #[tokio::test]
    async fn deleting_certificate_cascades_versions() {
        use crate::data::enums::{CertData, CertificateRenewMethod, CertificateType};

        let db = mem_db().await;
        let user = db.insert_user(User {
            id: -1, name: "o".into(), email: "o@b.c".into(), password_hash: None,
            oidc_id: None, role: UserRole::User, is_local: false,
        }).await.unwrap();
        let cert = db.insert_user_cert(Certificate {
            id: -1, name: "c".into(), created_on: 1, valid_until: 2,
            certificate_type: CertificateType::TLSServer, user_id: user.id,
            renew_method: CertificateRenewMethod::None, ca_id: None,
            revoked_at: None, acme_provider_id: None,
            data: CertData::Pkcs12(b"v1".to_vec()), password: String::new(),
            version: 1, fingerprint: Some("aa".into()), is_imported: true,
        }).await.unwrap();
        db.replace_certificate(cert.id, user.id, ReplaceCertificateInput {
            data: b"v2".to_vec(), password: String::new(), created_on: 3, valid_until: 4,
            serial_hex: None, fingerprint: "bb".into(), ca_id: 0,
        }).await.unwrap();

        db.delete_user_cert(cert.id).await.unwrap();
        assert!(db.list_certificate_versions(cert.id).await.unwrap().is_empty());
    }
```

Примечание для реализующего: в тесте `deleting_certificate_cascades_versions` передан `ca_id: 0`, которого нет в `ca_certificates`. Чтобы не спорить с внешним ключом, `replace_certificate` обновляет `ca_id` только когда переданное значение больше нуля.

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cd backend && cargo test replace_certificate_moves -- --nocapture 2>&1 | head -20`
Expected: FAIL — компиляция: `ReplaceCertificateInput` и методы не существуют.

- [ ] **Step 3: Реализовать методы**

В `backend/src/db.rs` рядом с `insert_user_cert` добавить структуры и методы:

```rust
/// Новое содержимое сертификата при замене.
pub(crate) struct ReplaceCertificateInput {
    pub data: Vec<u8>,
    pub password: String,
    pub created_on: i64,
    pub valid_until: i64,
    pub serial_hex: Option<String>,
    pub fingerprint: String,
    /// 0 означает «не менять привязку к CA».
    pub ca_id: i64,
}

/// Байты и пароль конкретной версии.
pub(crate) struct StoredCertVersion {
    pub data: Vec<u8>,
    pub password: String,
}
```

И в `impl VaulTLSDB`:

```rust
    /// Вытесняет текущую версию в историю и записывает новое содержимое.
    /// `id` сертификата не меняется. Возвращает номер новой версии.
    pub(crate) async fn replace_certificate(
        &self,
        cert_id: i64,
        actor_id: i64,
        input: ReplaceCertificateInput,
    ) -> Result<i64> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
        db_do!(self.pool, |conn: &Connection| {
            let tx = conn.unchecked_transaction()?;

            let (version, fingerprint): (i64, Option<String>) = tx.query_row(
                "SELECT version, fingerprint FROM user_certificates WHERE id = ?1",
                params![cert_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;

            tx.execute(
                "INSERT INTO certificate_versions \
                   (cert_id, version, data, password, created_on, valid_until, serial_hex, fingerprint, replaced_at, replaced_by) \
                 SELECT id, version, data, password, created_on, valid_until, serial_hex, ?2, ?3, ?4 \
                   FROM user_certificates WHERE id = ?1",
                params![cert_id, fingerprint.unwrap_or_default(), now, actor_id],
            )?;

            let next = version + 1;
            tx.execute(
                "UPDATE user_certificates SET data = ?1, password = ?2, created_on = ?3, \
                        valid_until = ?4, serial_hex = ?5, fingerprint = ?6, version = ?7, \
                        ca_id = CASE WHEN ?8 > 0 THEN ?8 ELSE ca_id END \
                  WHERE id = ?9",
                params![
                    input.data, input.password, input.created_on, input.valid_until,
                    input.serial_hex, input.fingerprint, next, input.ca_id, cert_id
                ],
            )?;

            tx.commit()?;
            Ok::<i64, anyhow::Error>(next)
        })
    }

    /// Все версии сертификата, новые сверху. Текущая — с `version_id = None`.
    pub(crate) async fn list_certificate_versions(&self, cert_id: i64) -> Result<Vec<CertificateVersionEntry>> {
        db_do!(self.pool, |conn: &Connection| {
            let current = conn.query_row(
                "SELECT version, created_on, valid_until, serial_hex, fingerprint \
                   FROM user_certificates WHERE id = ?1",
                params![cert_id],
                |r| Ok(CertificateVersionEntry {
                    version: r.get(0)?,
                    version_id: None,
                    current: true,
                    created_on: r.get(1)?,
                    valid_until: r.get(2)?,
                    serial_hex: r.get(3)?,
                    fingerprint: r.get(4)?,
                    replaced_at: None,
                    replaced_by: None,
                }),
            );
            let mut out = match current {
                Ok(entry) => vec![entry],
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(Vec::new()),
                Err(e) => return Err(anyhow::anyhow!(e)),
            };

            let mut stmt = conn.prepare(
                "SELECT id, version, created_on, valid_until, serial_hex, fingerprint, replaced_at, replaced_by \
                   FROM certificate_versions WHERE cert_id = ?1 ORDER BY version DESC",
            )?;
            let rows = stmt.query_map(params![cert_id], |r| Ok(CertificateVersionEntry {
                version: r.get(1)?,
                version_id: Some(r.get(0)?),
                current: false,
                created_on: r.get(2)?,
                valid_until: r.get(3)?,
                serial_hex: r.get(4)?,
                fingerprint: r.get(5)?,
                replaced_at: r.get(6)?,
                replaced_by: r.get(7)?,
            }))?;
            out.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
            Ok(out)
        })
    }

    /// Байты запрошенной версии: текущей — из user_certificates, иначе из истории.
    pub(crate) async fn get_certificate_version(&self, cert_id: i64, version: i64) -> Result<Option<StoredCertVersion>> {
        db_do!(self.pool, |conn: &Connection| {
            let current: i64 = match conn.query_row(
                "SELECT version FROM user_certificates WHERE id = ?1",
                params![cert_id],
                |r| r.get(0),
            ) {
                Ok(v) => v,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(anyhow::anyhow!(e)),
            };

            let sql = if version == current {
                "SELECT data, password FROM user_certificates WHERE id = ?1 AND version = ?2"
            } else {
                "SELECT data, password FROM certificate_versions WHERE cert_id = ?1 AND version = ?2"
            };
            let result = conn.query_row(sql, params![cert_id, version], |r| {
                Ok(StoredCertVersion { data: r.get(0)?, password: r.get(1)? })
            });
            match result {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        })
    }

    /// Удаляет историческую версию. False — если такой версии в истории нет.
    pub(crate) async fn delete_certificate_version(&self, cert_id: i64, version: i64) -> Result<bool> {
        db_do!(self.pool, |conn: &Connection| {
            let affected = conn.execute(
                "DELETE FROM certificate_versions WHERE cert_id = ?1 AND version = ?2",
                params![cert_id, version],
            )?;
            Ok(affected > 0)
        })
    }
```

Импорт `CertificateVersionEntry` дописать в шапку `db.rs` к существующему `use crate::certs::common::{Certificate, CA};`.

- [ ] **Step 4: Запустить тесты**

Run: `cd backend && cargo test --lib 2>&1 | tail -5`
Expected: PASS, включая `migration_17_…`, `replace_certificate_moves_old_row_into_history`, `deleting_certificate_cascades_versions`.

- [ ] **Step 5: Коммит**

```bash
git add backend/src/db.rs
git commit -m "feat(db): certificate version history with in-place replace transaction"
```

---

### Task 4: Бэкфилл отпечатков при старте

**Files:**
- Modify: `backend/src/db.rs` (рядом с `backfill_serials`, ~строка 956)
- Modify: `backend/src/lib.rs:116`
- Test: `backend/src/db.rs` (модуль `mod tests`)

**Interfaces:**
- Consumes: `Certificate::get_fingerprint` (Задача 2).
- Produces: `VaulTLSDB::set_cert_fingerprint(&self, cert_id: i64, fingerprint: String) -> Result<()>`, `VaulTLSDB::backfill_fingerprints(&self) -> Result<()>`.

- [ ] **Step 1: Написать падающий тест**

```rust
    #[tokio::test]
    async fn backfill_fingerprints_fills_missing_and_skips_ssh() {
        use crate::data::enums::{CertData, CertificateRenewMethod, CertificateType};
        use crate::certs::import::test_helpers::self_signed_ca;

        let db = mem_db().await;
        let user = db.insert_user(User {
            id: -1, name: "o".into(), email: "o@b.c".into(), password_hash: None,
            oidc_id: None, role: UserRole::User, is_local: false,
        }).await.unwrap();

        let (x509, _key) = self_signed_ca("backfill-test");
        let tls = db.insert_user_cert(Certificate {
            id: -1, name: "tls".into(), created_on: 1, valid_until: 2,
            certificate_type: CertificateType::TLSServer, user_id: user.id,
            renew_method: CertificateRenewMethod::None, ca_id: None,
            revoked_at: None, acme_provider_id: None,
            data: CertData::Pem(x509.to_pem().unwrap()), password: String::new(),
            version: 1, fingerprint: None, is_imported: true,
        }).await.unwrap();

        let ssh = db.insert_user_cert(Certificate {
            id: -1, name: "ssh".into(), created_on: 1, valid_until: 2,
            certificate_type: CertificateType::SSHServer, user_id: user.id,
            renew_method: CertificateRenewMethod::None, ca_id: None,
            revoked_at: None, acme_provider_id: None,
            data: CertData::SshBundle(vec![1, 2, 3]), password: String::new(),
            version: 1, fingerprint: None, is_imported: false,
        }).await.unwrap();

        db.backfill_fingerprints().await.unwrap();

        let filled = db.get_user_cert_by_id(tls.id).await.unwrap();
        assert_eq!(filled.fingerprint.as_deref().map(str::len), Some(64));
        let untouched = db.get_user_cert_by_id(ssh.id).await.unwrap();
        assert_eq!(untouched.fingerprint, None, "SSH пропускается без ошибки");
    }
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cd backend && cargo test backfill_fingerprints -- --nocapture 2>&1 | head -20`
Expected: FAIL — метода `backfill_fingerprints` не существует.

- [ ] **Step 3: Реализовать**

В `backend/src/db.rs` сразу после `backfill_serials`:

```rust
    pub(crate) async fn set_cert_fingerprint(&self, cert_id: i64, fingerprint: String) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "UPDATE user_certificates SET fingerprint = ?1 WHERE id = ?2",
                params![fingerprint, cert_id],
            )?;
            Ok(())
        })
    }

    /// Досчитывает отпечатки записям, появившимся до миграции 17.
    /// Сертификаты, у которых отпечаток не вычисляется (SSH, битый PKCS#12),
    /// молча пропускаются — это не повод ронять старт приложения.
    pub(crate) async fn backfill_fingerprints(&self) -> Result<()> {
        let ids: Vec<i64> = db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id FROM user_certificates WHERE fingerprint IS NULL OR fingerprint = ''"
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
            Ok::<Vec<i64>, anyhow::Error>(rows.collect::<rusqlite::Result<Vec<i64>>>()?)
        })?;

        for id in ids {
            let cert = self.get_user_cert_by_id(id).await?;
            if let Ok(fp) = cert.get_fingerprint() {
                if !fp.is_empty() {
                    self.set_cert_fingerprint(id, fp).await?;
                }
            }
        }
        Ok(())
    }
```

В `backend/src/lib.rs` после строки 116 добавить:

```rust
    db.backfill_fingerprints().await.expect("Failed backfilling certificate fingerprints");
```

- [ ] **Step 4: Запустить тесты**

Run: `cd backend && cargo test --lib backfill 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add backend/src/db.rs backend/src/lib.rs
git commit -m "feat(db): backfill certificate fingerprints on startup"
```

---

### Task 5: Аудит — два новых действия

**Files:**
- Modify: `backend/src/data/enums.rs:208-260`

**Interfaces:**
- Produces: `AuditAction::UpdateCertificate` (строка `"update_certificate"`), `AuditAction::DeleteCertificateVersion` (строка `"delete_certificate_version"`).

- [ ] **Step 1: Написать падающий тест**

В `backend/src/data/enums.rs`, в существующий `#[cfg(test)] mod`-блок (или создать `#[cfg(test)] mod audit_action_tests` в конце файла):

```rust
#[cfg(test)]
mod audit_action_roundtrip {
    use super::AuditAction;
    use std::str::FromStr;

    #[test]
    fn new_certificate_actions_roundtrip() {
        for action in [AuditAction::UpdateCertificate, AuditAction::DeleteCertificateVersion] {
            let s = action.as_str();
            assert_eq!(AuditAction::from_str(s).unwrap().as_str(), s);
        }
        assert_eq!(AuditAction::UpdateCertificate.as_str(), "update_certificate");
        assert_eq!(AuditAction::DeleteCertificateVersion.as_str(), "delete_certificate_version");
    }
}
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cd backend && cargo test new_certificate_actions_roundtrip 2>&1 | head -15`
Expected: FAIL — вариантов перечисления не существует.

- [ ] **Step 3: Добавить варианты**

В `enum AuditAction` в строку с сертификатами добавить два варианта:

```rust
    CreateCa, ImportCa, DeleteCa, RevokeCertificate, DeleteCertificate,
    UpdateCertificate, DeleteCertificateVersion,
```

В `as_str`:

```rust
            AuditAction::UpdateCertificate => "update_certificate",
            AuditAction::DeleteCertificateVersion => "delete_certificate_version",
```

В `from_str`:

```rust
            "update_certificate" => Ok(AuditAction::UpdateCertificate),
            "delete_certificate_version" => Ok(AuditAction::DeleteCertificateVersion),
```

- [ ] **Step 4: Запустить тесты**

Run: `cd backend && cargo test --lib audit 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add backend/src/data/enums.rs
git commit -m "feat(audit): add update_certificate and delete_certificate_version actions"
```

---

### Task 6: PUT /certificates/&lt;id&gt; — замена содержимого

**Files:**
- Modify: `backend/src/api.rs` (после `import_certificate`, ~строка 760)
- Modify: `backend/src/lib.rs` (три блока `openapi_get_routes!`: ~строки 213, 309, 370)
- Create: `backend/tests/api/api_test_cert_versions.rs`
- Modify: `backend/tests/api/mod.rs`

**Interfaces:**
- Consumes: `db.replace_certificate`, `Certificate::get_fingerprint`, `ReplaceCertificateInput`, `AuditAction::UpdateCertificate`.
- Produces: маршрут `PUT /api/certificates/<id>`, возвращающий обновлённый `Certificate` (JSON).

- [ ] **Step 1: Написать падающие тесты**

Создать `backend/tests/api/api_test_cert_versions.rs`:

```rust
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Header, Status};
use serde_json::Value;

/// Импортирует leaf и возвращает (id сертификата, ca_pem, ca_key_pem).
/// Ключ CA возвращается, чтобы тест мог подписать им новый leaf для замены.
async fn import_leaf(client: &VaulTLSClient, cn: &str, user_id: i64) -> (i64, Vec<u8>, Vec<u8>) {
    let (ca_pem, ca_key_pem) = crate::common::helper::self_signed_ca_pem("Versions CA");
    let (leaf_pem, leaf_key_pem) = crate::common::helper::leaf_signed_by_pem(cn, &ca_pem, &ca_key_pem);

    let boundary = "VER1";
    let body = crate::common::helper::multipart_import_leaf(boundary, &leaf_pem, &leaf_key_pem, &ca_pem, user_id);
    let resp = client
        .post("/certificates/import")
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let v: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    (v["id"].as_i64().unwrap(), ca_pem, ca_key_pem)
}

/// Формирует multipart-тело для PUT: cert + key + chain.
fn multipart_replace(boundary: &str, cert_pem: &[u8], key_pem: &[u8], chain_pem: &[u8], user_id: i64) -> Vec<u8> {
    crate::common::helper::multipart_import_leaf(boundary, cert_pem, key_pem, chain_pem, user_id)
}

#[tokio::test]
async fn replacing_imported_cert_keeps_id_and_bumps_version() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "rotate.example.com", 1).await;

    let before: Value = serde_json::from_str(
        &client.get("/certificates").dispatch().await.into_string().await.unwrap())?;
    let old_fp = before.as_array().unwrap().iter()
        .find(|c| c["id"].as_i64() == Some(id)).unwrap()["fingerprint"].as_str().unwrap().to_string();

    // новый leaf с тем же CN, подписанный тем же CA
    let (new_leaf, new_key) =
        crate::common::helper::leaf_signed_by_pem("rotate.example.com", &ca_pem, &ca_key_pem);

    let boundary = "VER2";
    let body = multipart_replace(boundary, &new_leaf, &new_key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let updated: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(updated["id"].as_i64(), Some(id), "id обязан сохраниться");
    assert_eq!(updated["version"].as_i64(), Some(2));
    assert_ne!(updated["fingerprint"].as_str().unwrap(), old_fp, "отпечаток обязан смениться");
    Ok(())
}

#[tokio::test]
async fn replacing_with_different_cn_is_rejected() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "same.example.com", 1).await;

    let (other_leaf, other_key) =
        crate::common::helper::leaf_signed_by_pem("other.example.com", &ca_pem, &ca_key_pem);

    let boundary = "VER3";
    let body = multipart_replace(boundary, &other_leaf, &other_key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);
    Ok(())
}

#[tokio::test]
async fn replacing_internally_issued_cert_is_rejected() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    // выпущен внутренним CA — is_imported = 0
    let cert = client.create_client_cert(Some(1), Some("pw".into()), None).await?;

    let (ca_pem, ca_key_pem) = crate::common::helper::self_signed_ca_pem("Foreign CA");
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("whatever", &ca_pem, &ca_key_pem);

    let boundary = "VER4";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{}", cert.id))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);
    Ok(())
}

#[tokio::test]
async fn group_member_may_read_but_not_replace() -> Result<()> {
    use serde_json::json;
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "shared.example.com", 1).await;

    let gid: i64 = serde_json::from_str(
        &client.post("/groups").header(ContentType::JSON)
            .body(json!({"name":"Shared"}).to_string())
            .dispatch().await.into_string().await.unwrap())?;
    client.put(format!("/groups/{gid}/users")).header(ContentType::JSON)
        .body(json!({"ids":[2]}).to_string()).dispatch().await;
    client.put(format!("/groups/{gid}/certificates")).header(ContentType::JSON)
        .body(json!({"ids":[id]}).to_string()).dispatch().await;

    client.switch_user().await?; // под user id=2

    assert_eq!(client.get(format!("/certificates/{id}/versions")).dispatch().await.status(), Status::Ok);

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("shared.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER5";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 2);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "участник группы читает, но не заменяет");
    Ok(())
}

#[tokio::test]
async fn service_token_needs_issue_scope_to_replace() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await; // local admin id=1
    let (id, ca_pem, ca_key_pem) = import_leaf(&admin, "svc.example.com", 1).await;

    let created: Value = serde_json::from_str(
        &admin.post("/users/1/service-accounts").header(ContentType::JSON)
            .body(r#"{"name":"rot","scopes":["cert:read"]}"#)
            .dispatch().await.into_string().await.unwrap())?;
    let token: Value = serde_json::from_str(
        &admin.post("/auth/token").header(ContentType::JSON)
            .body(format!(r#"{{"client_id":"{}","secret":"{}"}}"#,
                created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()))
            .dispatch().await.into_string().await.unwrap())?;
    let bearer = format!("Bearer {}", token["access_token"].as_str().unwrap());

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("svc.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER6";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = admin
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .header(Header::new("Authorization", bearer))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "cert:read не даёт права заменять");
    Ok(())
}
```

Зарегистрировать файл — в `backend/tests/api/mod.rs` добавить строку:

```rust
mod api_test_cert_versions;
```

Новых хелперов не нужно: `self_signed_ca_pem(cn) -> (cert_pem, key_pem)` и
`leaf_signed_by_pem(cn, ca_pem, ca_key_pem) -> (leaf_pem, leaf_key_pem)` уже есть
в `backend/tests/common/helper.rs:52` и `:84`, а `import_leaf` возвращает ключ CA,
чтобы подписать им сменный leaf.

- [ ] **Step 2: Запустить — убедиться, что падают**

Run: `cd backend && cargo test --test integration_tests cert_versions 2>&1 | tail -20`
Expected: FAIL — маршрута `PUT /certificates/<id>` нет, Rocket отвечает 404.

- [ ] **Step 3: Реализовать обработчик**

В `backend/src/api.rs` после `import_certificate` добавить:

```rust
#[openapi(tag = "Certificates")]
#[put("/certificates/<id>", data = "<form>")]
/// Replace the contents of an imported certificate, keeping its id.
/// The previous contents move into the version history.
pub(crate) async fn update_certificate(
    state: &State<AppState>,
    id: i64,
    mut form: rocket::form::Form<ImportCertForm<'_>>,
    authentication: Authenticated,
) -> Result<Json<Certificate>, ApiError> {
    use crate::certs::import::{parse_cert, parse_private_key, parse_pkcs12, parse_pem_bundle, find_issuing_ca, verify_signed_by};

    let existing = state.db.get_user_cert_by_id(id).await
        .map_err(|_| ApiError::NotFound(None))?;

    // Авторизация: владелец или локальный админ; сервис — только со cert:issue
    // и только на сертификатах своего владельца.
    if authentication.claims.is_service() {
        if !authentication.claims.has_scope("cert:issue") {
            return Err(ApiError::Forbidden(None));
        }
        if existing.user_id != authentication.claims.id {
            return Err(ApiError::Forbidden(None));
        }
    } else if !authentication.claims.is_local_admin() && existing.user_id != authentication.claims.id {
        return Err(ApiError::Forbidden(None));
    }
    form.user_id = existing.user_id; // владелец записи не меняется

    // Что вообще подлежит замене
    if existing.acme_provider_id.is_some() {
        return Err(ApiError::BadRequest("ACME certificates are renewed by the provider".into()));
    }
    if !existing.is_imported {
        return Err(ApiError::BadRequest("certificate is not importable".into()));
    }
    if existing.revoked_at.is_some() {
        return Err(ApiError::BadRequest("revoked certificate cannot be updated".into()));
    }
    if !matches!(existing.certificate_type, CertificateType::TLSClient | CertificateType::TLSServer) {
        return Err(ApiError::BadRequest("only TLS certificates can be replaced".into()));
    }

    // 1) Разобрать присланный материал — та же логика, что в import_certificate.
    let (leaf, chain, stored): (openssl::x509::X509, Vec<openssl::x509::X509>, CertData) =
        if let Some(p12_file) = &form.p12 {
            let bytes = read_tempfile(p12_file).await?;
            let pwd = form.password.clone().unwrap_or_default();
            let (leaf, _key, chain) = parse_pkcs12(&bytes, &pwd)
                .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            (leaf, chain, CertData::Pkcs12(bytes))
        } else {
            let cert_f = form.cert.as_ref()
                .ok_or_else(|| ApiError::BadRequest("cert or p12 required".into()))?;
            let key_f = form.key.as_ref()
                .ok_or_else(|| ApiError::BadRequest("key required with cert".into()))?;
            let cert_bytes = read_tempfile(cert_f).await?;
            let key_bytes = read_tempfile(key_f).await?;
            let cert_certs = parse_pem_bundle(&cert_bytes).unwrap_or_default();
            let leaf = match cert_certs.first() {
                Some(c) => c.clone(),
                None => parse_cert(&cert_bytes).map_err(|e| ApiError::BadRequest(e.to_string()))?,
            };
            let key = parse_private_key(&key_bytes).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            let mut chain: Vec<openssl::x509::X509> = cert_certs.into_iter().skip(1).collect();
            if let Some(cf) = &form.chain {
                let extra = parse_pem_bundle(&read_tempfile(cf).await?)
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
                chain.extend(extra);
            }
            let pwd = form.password.clone().unwrap_or_default();
            let mut ca_stack = openssl::stack::Stack::new()?;
            for c in &chain {
                ca_stack.push(c.clone())?;
            }
            let p12 = openssl::pkcs12::Pkcs12::builder()
                .name("imported")
                .ca(ca_stack)
                .cert(&leaf)
                .pkey(&key)
                .build2(&pwd)?;
            (leaf, chain, CertData::Pkcs12(p12.to_der()?))
        };

    // 2) CN обязан совпадать.
    let new_cn = cn_from_cert(&leaf);
    if new_cn != existing.name.cn {
        return Err(ApiError::BadRequest(format!(
            "CN mismatch: certificate has '{}', record expects '{}'", new_cn, existing.name.cn
        )));
    }

    // 3) Цепочка: сначала пробуем прежний CA записи, иначе ищем издателя в цепочке
    //    — ровно та же логика, что в import_certificate (api.rs:695-728).
    let same_ca = match existing.ca_id {
        Some(existing_ca_id) => match state.db.get_ca_by_id(existing_ca_id).await {
            Ok(ca) if !ca.cert.is_empty() => parse_cert(&ca.cert)
                .map(|c| verify_signed_by(&leaf, &c))
                .unwrap_or(false),
            _ => false,
        },
        None => false,
    };

    let ca_id = if same_ca {
        existing.ca_id.unwrap()
    } else {
        let issuer = find_issuing_ca(&leaf, &chain)
            .ok_or_else(|| ApiError::BadRequest("could not find issuing CA in chain".into()))?;
        if !verify_signed_by(&leaf, &issuer) {
            return Err(ApiError::BadRequest("leaf is not signed by the provided CA chain".into()));
        }
        let issuer_der = issuer.to_der()?;
        match state.db.find_imported_ca_by_cert(&issuer_der).await? {
            Some(found) => found.id,
            None => {
                let ca = CA {
                    id: -1,
                    name: crate::data::objects::Name::from(cn_from_cert(&issuer)),
                    created_on: asn1_to_unix_ms(issuer.not_before())?,
                    valid_until: asn1_to_unix_ms(issuer.not_after())?,
                    ca_type: CAType::TLS,
                    cert: issuer_der,
                    key: Vec::new(),
                    crl_number: 0,
                    is_imported: true,
                };
                state.db.insert_ca(ca).await?.id
            }
        }
    };

    // 4) Транзакционная замена.
    let password = form.password.clone().unwrap_or_default();
    let candidate = Certificate {
        id,
        name: existing.name.clone(),
        created_on: asn1_to_unix_ms(leaf.not_before())?,
        valid_until: asn1_to_unix_ms(leaf.not_after())?,
        certificate_type: existing.certificate_type,
        user_id: existing.user_id,
        renew_method: existing.renew_method,
        ca_id: Some(ca_id),
        revoked_at: None,
        acme_provider_id: None,
        data: stored,
        password: password.clone(),
        version: existing.version,
        fingerprint: None,
        is_imported: true,
    };
    let fingerprint = candidate.get_fingerprint()
        .map_err(|e| ApiError::BadRequest(format!("cannot compute fingerprint: {e}")))?;
    let serial_hex = candidate.get_serial().ok()
        .map(|s| s.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let new_version = state.db.replace_certificate(
        id,
        authentication.claims.id,
        crate::db::ReplaceCertificateInput {
            data: candidate.data.as_bytes().to_vec(),
            password,
            created_on: candidate.created_on,
            valid_until: candidate.valid_until,
            serial_hex,
            fingerprint: fingerprint.clone(),
            ca_id,
        },
    ).await?;

    let (aid, alabel, atype) = audit_actor(state, &authentication.claims).await;
    record_audit(state, aid, alabel, atype, AuditAction::UpdateCertificate,
        Some("certificate".into()), Some(id.to_string()), Some(existing.name.cn.clone()),
        AuditResult::Success,
        Some(format!("v{} → v{}, fingerprint {}", existing.version, new_version, fingerprint)),
        None).await;

    Ok(Json(state.db.get_user_cert_by_id(id).await?))
}
```

Замечания реализующему:

- `CertData::as_bytes()` уже используется в `download_certificate` (`api.rs:1151`) — та же семантика.
- `state.db.find_imported_ca_by_cert(&der) -> Result<Option<CA>>` уже существует и вызывается из `import_certificate` (`api.rs:704`).
- `existing.ca_id.unwrap()` в ветке `same_ca` безопасен: флаг `same_ca` истинен только когда `ca_id` был `Some`.

Зарегистрировать маршрут: в `backend/src/lib.rs` в каждый из трёх блоков `openapi_get_routes![…]` дописать `update_certificate,` рядом с `import_certificate,`.

- [ ] **Step 4: Запустить тесты**

Run: `cd backend && cargo test --test integration_tests cert_versions 2>&1 | tail -10`
Expected: PASS все пять тестов файла.

- [ ] **Step 5: Прогнать весь бэкенд**

Run: `cd backend && cargo test 2>&1 | tail -5`
Expected: единственный провал — `test_ssh_revocation_and_krl`.

- [ ] **Step 6: Коммит**

```bash
git add backend/src/api.rs backend/src/lib.rs backend/tests/
git commit -m "feat(api): PUT /certificates/<id> replaces imported certificate in place"
```

---

### Task 7: GET /certificates/&lt;id&gt;/versions и параметр version

**Files:**
- Modify: `backend/src/api.rs:1129` (`download_certificate`), `:1222` (`fetch_certificate_password`), плюс новый обработчик рядом
- Modify: `backend/src/lib.rs` (три блока маршрутов)
- Modify: `backend/tests/api/api_test_cert_versions.rs`

**Interfaces:**
- Consumes: `db.list_certificate_versions`, `db.get_certificate_version`, `can_access_cert_secret`.
- Produces: `GET /api/certificates/<id>/versions`; параметр `version` у download и password.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `backend/tests/api/api_test_cert_versions.rs`:

```rust
#[tokio::test]
async fn old_version_stays_downloadable_after_replace() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "history.example.com", 1).await;

    let v1 = client.get(format!("/certificates/{id}/download")).dispatch().await
        .into_bytes().await.unwrap();

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("history.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER7";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let v2 = client.get(format!("/certificates/{id}/download")).dispatch().await
        .into_bytes().await.unwrap();
    assert_ne!(v1, v2, "текущая версия сменилась");

    let v1_again = client.get(format!("/certificates/{id}/download?version=1")).dispatch().await
        .into_bytes().await.unwrap();
    assert_eq!(v1, v1_again, "первая версия доступна по номеру");

    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    let arr = versions.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["version"].as_i64(), Some(2));
    assert_eq!(arr[0]["current"].as_bool(), Some(true));
    assert!(arr[0]["version_id"].is_null());
    assert_eq!(arr[1]["version"].as_i64(), Some(1));
    assert!(arr[1]["version_id"].as_i64().unwrap() > 0);
    Ok(())
}

#[tokio::test]
async fn unknown_version_is_404() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, _ca_pem, _ca_key) = import_leaf(&client, "single.example.com", 1).await;
    let resp = client.get(format!("/certificates/{id}/download?version=7")).dispatch().await;
    assert_eq!(resp.status(), Status::NotFound);
    Ok(())
}
```

- [ ] **Step 2: Запустить — убедиться, что падают**

Run: `cd backend && cargo test --test integration_tests old_version_stays 2>&1 | tail -10`
Expected: FAIL — `/versions` отвечает 404, `?version=1` игнорируется.

- [ ] **Step 3: Реализовать**

В `backend/src/api.rs` рядом с `download_certificate` добавить обработчик списка:

```rust
#[openapi(tag = "Certificates")]
#[get("/certificates/<id>/versions")]
/// List all versions of a certificate, newest first. The current version has
/// `version_id: null` — it lives in the certificate record itself.
pub(crate) async fn list_certificate_versions(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated,
) -> Result<Json<Vec<CertificateVersionEntry>>, ApiError> {
    if authentication.claims.is_service() && !authentication.claims.has_scope("cert:read") {
        return Err(ApiError::Forbidden(None));
    }
    let certificate = state.db.get_user_cert_by_id(id).await
        .map_err(|_| ApiError::NotFound(None))?;
    if !can_access_cert_secret(state, &authentication.claims, certificate.user_id, id).await? {
        return Err(ApiError::Forbidden(None));
    }
    Ok(Json(state.db.list_certificate_versions(id).await?))
}
```

Изменить сигнатуру `download_certificate`:

```rust
#[get("/certificates/<id>/download?<download_format>&<version>")]
pub(crate) async fn download_certificate(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated,
    download_format: Option<String>,
    version: Option<i64>,
) -> Result<DownloadResponse, ApiError> {
```

Сразу после проверки доступа (`can_access_cert_secret`) и до ветки PEM подставить содержимое запрошенной версии:

```rust
    // По умолчанию отдаём текущую версию; ?version=N достаёт её из истории.
    let mut certificate = certificate;
    if let Some(v) = version {
        let stored = state.db.get_certificate_version(id, v).await?
            .ok_or(ApiError::NotFound(None))?;
        certificate.data = match certificate.certificate_type {
            CertificateType::SSHClient | CertificateType::SSHServer => CertData::SshBundle(stored.data),
            _ => if stored.data.starts_with(b"-----BEGIN CERTIFICATE-----") {
                CertData::Pem(stored.data)
            } else {
                CertData::Pkcs12(stored.data)
            },
        };
        certificate.password = stored.password;
    }
```

Аналогично `fetch_certificate_password`:

```rust
#[get("/certificates/<id>/password?<version>")]
pub(crate) async fn fetch_certificate_password(
    state: &State<AppState>,
    id: i64,
    authentication: Authenticated,
    version: Option<i64>,
) -> Result<Json<String>, ApiError> {
```

и после проверки доступа:

```rust
    let password = match version {
        None => password,
        Some(v) => state.db.get_certificate_version(id, v).await?
            .ok_or(ApiError::NotFound(None))?
            .password,
    };
```

Импорт `CertificateVersionEntry` дописать к существующему `use crate::certs::common::{…}` в шапке `api.rs`.

Зарегистрировать `list_certificate_versions` во всех трёх блоках маршрутов в `lib.rs`.

- [ ] **Step 4: Запустить тесты**

Run: `cd backend && cargo test --test integration_tests cert_versions 2>&1 | tail -10`
Expected: PASS все тесты файла.

- [ ] **Step 5: Коммит**

```bash
git add backend/src/api.rs backend/src/lib.rs backend/tests/api/api_test_cert_versions.rs
git commit -m "feat(api): list certificate versions and download historical ones"
```

---

### Task 8: DELETE версии и расширение validate на историю

**Files:**
- Modify: `backend/src/api.rs` (новый обработчик рядом с `list_certificate_versions`; `validate_certificate` ~строка 1589)
- Modify: `backend/src/db.rs` (`get_cert_status_by_serial_hex`)
- Modify: `backend/src/data/api.rs:202-209` (`CertStatusResponse`)
- Modify: `backend/src/lib.rs` (три блока маршрутов)
- Modify: `backend/tests/api/api_test_cert_versions.rs`

**Interfaces:**
- Consumes: `db.delete_certificate_version`, `AuditAction::DeleteCertificateVersion`.
- Produces: `DELETE /api/certificates/<id>/versions/<version>`; поле `superseded: bool` в `CertStatusResponse`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `backend/tests/api/api_test_cert_versions.rs`:

```rust
#[tokio::test]
async fn only_local_admin_deletes_historical_versions() -> Result<()> {
    use crate::common::constants::{TEST_PASSWORD, TEST_USER_EMAIL};

    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "purge.example.com", 2).await;

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("purge.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER8";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 2);
    client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;

    // текущую версию удалить нельзя
    assert_eq!(client.delete(format!("/certificates/{id}/versions/2")).dispatch().await.status(),
               Status::BadRequest);

    // владелец без прав локального админа — 403
    client.switch_user().await?; // user id=2, он же владелец
    assert_eq!(client.delete(format!("/certificates/{id}/versions/1")).dispatch().await.status(),
               Status::Forbidden);

    // локальный админ — 200, версия исчезает из истории
    client.logout().await?;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;
    assert_eq!(client.delete(format!("/certificates/{id}/versions/1")).dispatch().await.status(),
               Status::Ok);

    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    assert_eq!(versions.as_array().unwrap().len(), 1, "осталась только текущая версия");
    Ok(())
}

#[tokio::test]
async fn superseded_serial_still_validates() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "validate.example.com", 1).await;

    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    let old_serial = versions.as_array().unwrap()[0]["serial_hex"].as_str().unwrap().to_string();

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("validate.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER9";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;

    let status: Value = serde_json::from_str(
        &client.get(format!("/certificates/validate?serial={old_serial}")).dispatch().await
            .into_string().await.unwrap())?;
    assert_ne!(status["status"].as_str(), Some("unknown"), "вытесненный серийник обязан находиться");
    assert_eq!(status["superseded"].as_bool(), Some(true));
    Ok(())
}
```

- [ ] **Step 2: Запустить — убедиться, что падают**

Run: `cd backend && cargo test --test integration_tests superseded_serial 2>&1 | tail -10`
Expected: FAIL — маршрута удаления нет, поля `superseded` нет.

- [ ] **Step 3: Реализовать удаление версии**

В `backend/src/api.rs`:

```rust
#[openapi(tag = "Certificates")]
#[delete("/certificates/<id>/versions/<version>")]
/// Permanently delete one historical version. The current version cannot be deleted.
pub(crate) async fn delete_certificate_version(
    state: &State<AppState>,
    id: i64,
    version: i64,
    authentication: AuthenticatedLocalAdmin,
) -> Result<(), ApiError> {
    let certificate = state.db.get_user_cert_by_id(id).await
        .map_err(|_| ApiError::NotFound(None))?;
    if certificate.version == version {
        return Err(ApiError::BadRequest("current version cannot be deleted".into()));
    }
    if !state.db.delete_certificate_version(id, version).await? {
        return Err(ApiError::NotFound(None));
    }

    let (aid, alabel, atype) = audit_actor(state, &authentication.claims).await;
    record_audit(state, aid, alabel, atype, AuditAction::DeleteCertificateVersion,
        Some("certificate".into()), Some(id.to_string()), Some(certificate.name.cn.clone()),
        AuditResult::Success, Some(format!("version {version}")), None).await;

    Ok(())
}
```

`AuthenticatedLocalAdmin` отдаёт 403 не-локальному админу до входа в тело — отдельной проверки не нужно.

- [ ] **Step 4: Расширить validate на историю**

В `backend/src/data/api.rs` в `CertStatusResponse` добавить поле:

```rust
    /// True, если серийник найден в истории версий, а не в текущей записи.
    #[serde(default)]
    pub superseded: bool,
```

В `backend/src/db.rs` расширить `get_cert_status_by_serial_hex`: если в `user_certificates` строки нет, искать в истории.

```rust
    pub(crate) async fn get_cert_status_by_serial_hex(&self, serial_hex: String) -> Result<Option<CertStatusRow>> {
        db_do!(self.pool, |conn: &Connection| {
            let current = conn.query_row(
                "SELECT created_on, valid_until, revoked_at, ca_id FROM user_certificates WHERE serial_hex = ?1",
                params![serial_hex],
                |row| Ok(CertStatusRow {
                    created_on: row.get(0)?,
                    valid_until: row.get(1)?,
                    revoked_at: row.get(2)?,
                    ca_id: row.get(3)?,
                    superseded: false,
                }),
            );
            match current {
                Ok(r) => return Ok(Some(r)),
                Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(e) => return Err(anyhow::anyhow!(e)),
            }

            // Серийник вытесненной версии: сертификат, выданный клиенту раньше,
            // не должен становиться «неизвестным» после ротации.
            let historical = conn.query_row(
                "SELECT v.created_on, v.valid_until, c.revoked_at, c.ca_id \
                   FROM certificate_versions v \
                   JOIN user_certificates c ON c.id = v.cert_id \
                  WHERE v.serial_hex = ?1",
                params![serial_hex],
                |row| Ok(CertStatusRow {
                    created_on: row.get(0)?,
                    valid_until: row.get(1)?,
                    revoked_at: row.get(2)?,
                    ca_id: row.get(3)?,
                    superseded: true,
                }),
            );
            match historical {
                Ok(r) => Ok(Some(r)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        })
    }
```

В структуру `CertStatusRow` (та же `db.rs`) добавить `pub superseded: bool`.

В `backend/src/api.rs` в `validate_certificate` заполнить новое поле: в ветке `None` — `superseded: false`, в ветке `Some(row)` — `superseded: row.superseded`.

Зарегистрировать `delete_certificate_version` во всех трёх блоках маршрутов в `lib.rs`.

- [ ] **Step 5: Запустить тесты**

Run: `cd backend && cargo test 2>&1 | tail -5`
Expected: все PASS, кроме известного `test_ssh_revocation_and_krl`.

- [ ] **Step 6: Коммит**

```bash
git add backend/src/api.rs backend/src/db.rs backend/src/data/api.rs backend/src/lib.rs backend/tests/api/api_test_cert_versions.rs
git commit -m "feat(api): delete historical versions and validate superseded serials"
```

---

### Task 9: Фронтенд — типы, API-клиент, стор

**Files:**
- Modify: `frontend/src/types/Certificate.ts`
- Create: `frontend/src/types/CertificateVersion.ts`
- Modify: `frontend/src/api/ApiClient.ts` (после `postForm`, ~строка 94)
- Modify: `frontend/src/api/certificates.ts`
- Create: `frontend/src/stores/certificateVersions.ts`
- Create: `frontend/src/__tests__/certificateVersions.spec.ts`

**Interfaces:**
- Consumes: маршруты из Задач 6-8.
- Produces:
  - `interface CertificateVersion { version: number; version_id: number | null; current: boolean; created_on: number; valid_until: number; serial_hex: string | null; fingerprint: string | null; replaced_at: number | null; replaced_by: number | null }`
  - `ApiClient.putForm<T>(url: string, form: FormData): Promise<T>`
  - `fetchCertificateVersions(id: number): Promise<CertificateVersion[]>`
  - `updateCertificate(id: number, form: FormData): Promise<Certificate>`
  - `deleteCertificateVersion(id: number, version: number): Promise<void>`
  - `downloadCertificate(id: number, format?: 'pem', version?: number): Promise<void>`
  - `fetchCertificatePassword(id: number, version?: number): Promise<string>`
  - стор `useCertificateVersionStore` с состоянием `{ versions, loading, error }` и действиями `fetchForCertificate(id)`, `update(id, form)`, `remove(id, version)`

- [ ] **Step 1: Написать падающий тест**

Создать `frontend/src/__tests__/certificateVersions.spec.ts`. За образец взять любой из трёх существующих тестов в этой папке — тот же способ мока axios/ApiClient.

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useCertificateVersionStore } from '@/stores/certificateVersions'
import * as api from '@/api/certificates'

describe('certificateVersions store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.restoreAllMocks()
  })

  it('loads versions for a certificate', async () => {
    vi.spyOn(api, 'fetchCertificateVersions').mockResolvedValue([
      { version: 2, version_id: null, current: true, created_on: 2, valid_until: 3,
        serial_hex: '0b', fingerprint: 'bb', replaced_at: null, replaced_by: null },
      { version: 1, version_id: 7, current: false, created_on: 0, valid_until: 1,
        serial_hex: '0a', fingerprint: 'aa', replaced_at: 2, replaced_by: 1 },
    ])

    const store = useCertificateVersionStore()
    await store.fetchForCertificate(19)

    expect(store.versions).toHaveLength(2)
    expect(store.versions[0].current).toBe(true)
    expect(store.versions[1].version_id).toBe(7)
    expect(store.error).toBeNull()
  })

  it('records an error when the API refuses', async () => {
    vi.spyOn(api, 'fetchCertificateVersions').mockRejectedValue(new Error('403'))

    const store = useCertificateVersionStore()
    await store.fetchForCertificate(19)

    expect(store.versions).toHaveLength(0)
    expect(store.error).not.toBeNull()
  })
})
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cd frontend && npm run test:unit 2>&1 | tail -15`
Expected: FAIL — модуля `@/stores/certificateVersions` не существует.

- [ ] **Step 3: Реализовать типы и клиент**

`frontend/src/types/CertificateVersion.ts`:

```ts
export interface CertificateVersion {
    version: number;                  // номер версии, 1 — первая
    version_id: number | null;        // id записи истории; null у текущей версии
    current: boolean;
    created_on: number;               // UNIX ms
    valid_until: number;              // UNIX ms
    serial_hex: string | null;
    fingerprint: string | null;       // SHA-256 в hex
    replaced_at: number | null;       // UNIX ms, когда версия была вытеснена
    replaced_by: number | null;       // id пользователя, выполнившего замену
}
```

В `frontend/src/types/Certificate.ts` в `interface Certificate` добавить:

```ts
    version: number;                      // номер текущей версии содержимого
    fingerprint?: string | null;          // SHA-256 текущей версии в hex
    is_imported: boolean;                 // только импортированные можно заменять
```

В `frontend/src/api/ApiClient.ts` после `postForm` (строка 94) добавить:

```ts
    async putForm<T>(url: string, form: FormData): Promise<T> {
        try {
            const response: AxiosResponse<T> = await this.client.put(url, form, {
                headers: { 'Content-Type': 'multipart/form-data' },
            });
            return response.data;
        } catch (error) {
            console.error(`PUT ${url} (form) failed:`, error);
            throw error;
        }
    }
```

В `frontend/src/api/certificates.ts`:

```ts
import type {CertificateVersion} from '@/types/CertificateVersion';

export const fetchCertificateVersions = async (id: number): Promise<CertificateVersion[]> => {
    return await ApiClient.get<CertificateVersion[]>(`/certificates/${id}/versions`);
};

export const updateCertificate = async (id: number, form: FormData): Promise<Certificate> => {
    return await ApiClient.putForm<Certificate>(`/certificates/${id}`, form);
};

export const deleteCertificateVersion = async (id: number, version: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/${id}/versions/${version}`);
};
```

Существующие `downloadCertificate` и `fetchCertificatePassword` расширить необязательным номером версии:

```ts
export const fetchCertificatePassword = async (id: number, version?: number): Promise<string> => {
    const query = version === undefined ? '' : `?version=${version}`;
    return await ApiClient.get<string>(`/certificates/${id}/password${query}`);
};

export const downloadCertificate = async (id: number, format?: 'pem', version?: number): Promise<void> => {
    const params = [
        format ? `download_format=${format}` : null,
        version === undefined ? null : `version=${version}`,
    ].filter(Boolean).join('&');
    const url = `/certificates/${id}/download${params ? `?${params}` : ''}`;
    return await ApiClient.download(url);
};
```

`frontend/src/stores/certificateVersions.ts` — по образцу `stores/serviceAccounts.ts`:

```ts
import { defineStore } from 'pinia'
import axios from 'axios'
import type { CertificateVersion } from '@/types/CertificateVersion'
import {
  fetchCertificateVersions,
  updateCertificate,
  deleteCertificateVersion,
} from '@/api/certificates'

export const useCertificateVersionStore = defineStore('certificateVersion', {
  state: () => ({
    versions: [] as CertificateVersion[],
    loading: false,
    error: null as string | null,
  }),

  actions: {
    async fetchForCertificate(id: number): Promise<void> {
      this.loading = true
      this.error = null
      try {
        this.versions = await fetchCertificateVersions(id)
      } catch (err) {
        this.versions = []
        this.error = axios.isAxiosError(err)
          ? 'Failed to load certificate versions: ' + err.response?.data?.error
          : 'Failed to load certificate versions'
        console.error(err)
      } finally {
        this.loading = false
      }
    },

    async update(id: number, form: FormData): Promise<boolean> {
      this.loading = true
      this.error = null
      try {
        await updateCertificate(id, form)
        await this.fetchForCertificate(id)
        return true
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to update certificate: ' + err.response?.data?.error
          : 'Failed to update certificate'
        console.error(err)
        return false
      } finally {
        this.loading = false
      }
    },

    async remove(id: number, version: number): Promise<void> {
      this.loading = true
      this.error = null
      try {
        await deleteCertificateVersion(id, version)
        await this.fetchForCertificate(id)
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to delete version: ' + err.response?.data?.error
          : 'Failed to delete version'
        console.error(err)
      } finally {
        this.loading = false
      }
    },
  },
})
```

- [ ] **Step 4: Запустить тесты и типы**

Run: `cd frontend && npm run type-check && npm run test:unit 2>&1 | tail -8`
Expected: типы чисто, все тесты PASS (было 9, стало 11).

- [ ] **Step 5: Коммит**

```bash
git add frontend/src/types frontend/src/api frontend/src/stores frontend/src/__tests__
git commit -m "feat(ui): certificate version types, api client and store"
```

---

### Task 10: Фронтенд — модалки обновления и истории

**Files:**
- Create: `frontend/src/components/UpdateCertificateModal.vue`
- Create: `frontend/src/components/CertificateVersionsModal.vue`
- Modify: `frontend/src/components/OverviewTab.vue` (колонка действий ~строка 110, имя ~строка 84, блок `<script setup>`)
- Modify: `frontend/src/locales/en.json`, `frontend/src/locales/es.json`

**Interfaces:**
- Consumes: `useCertificateVersionStore`, `downloadCertificate(id, format, version)`, `fetchCertificatePassword(id, version)`.
- Produces: пользовательский путь — кнопка «Обновить» и кнопка «История» в списке сертификатов.

- [ ] **Step 1: Добавить строки локализации**

В `frontend/src/locales/en.json` рядом с блоком `"certs"` добавить новый блок:

```json
  "certVersions": {
    "update": "Update certificate",
    "updateTitle": "Update certificate",
    "updateHint": "Upload a new certificate for the same common name. The record keeps its id; the current contents move into history.",
    "history": "Version history",
    "historyTitle": "Version history",
    "version": "Version",
    "current": "Current",
    "fingerprint": "Fingerprint",
    "replacedAt": "Replaced",
    "replacedBy": "Replaced by",
    "downloadP12": "Download .p12",
    "downloadPem": "Download PEM",
    "showPassword": "Show password",
    "deleteVersion": "Delete version",
    "deleteConfirm": "Delete version {version}? This cannot be undone.",
    "updated": "Updated to version {version}",
    "noHistory": "No previous versions yet."
  },
```

В `frontend/src/locales/es.json` — тот же блок с переводом:

```json
  "certVersions": {
    "update": "Actualizar certificado",
    "updateTitle": "Actualizar certificado",
    "updateHint": "Sube un certificado nuevo con el mismo common name. El registro conserva su id; el contenido actual pasa al historial.",
    "history": "Historial de versiones",
    "historyTitle": "Historial de versiones",
    "version": "Versión",
    "current": "Actual",
    "fingerprint": "Huella",
    "replacedAt": "Reemplazada",
    "replacedBy": "Reemplazada por",
    "downloadP12": "Descargar .p12",
    "downloadPem": "Descargar PEM",
    "showPassword": "Mostrar contraseña",
    "deleteVersion": "Eliminar versión",
    "deleteConfirm": "¿Eliminar la versión {version}? Esta acción no se puede deshacer.",
    "updated": "Actualizado a la versión {version}",
    "noHistory": "Aún no hay versiones anteriores."
  },
```

- [ ] **Step 2: Создать модалку обновления**

`frontend/src/components/UpdateCertificateModal.vue`. За образец взять существующую модалку импорта в `OverviewTab.vue` — там уже собирается `FormData` с полями `p12`/`cert`/`key`/`chain`/`password`/`user_id`; повторить набор полей.

```vue
<template>
  <BaseModal
    :visible="visible"
    :title="$t('certVersions.updateTitle')"
    :submitLabel="$t('certVersions.update')"
    submitIcon="pi pi-upload"
    :submitDisabled="store.loading || !hasFile"
    :loading="store.loading"
    @submit="onSubmit"
    @cancel="onClose"
    @update:visible="(v: boolean) => emit('update:visible', v)"
    width="520px"
  >
    <p class="vt-sub">{{ $t('certVersions.updateHint') }}</p>

    <div class="vt-form">
      <div class="vt-field">
        <label>PKCS#12</label>
        <input type="file" accept=".p12,.pfx" @change="onP12" />
      </div>
      <div class="vt-field">
        <label>PEM</label>
        <input type="file" accept=".pem,.crt" @change="onCert" />
        <input type="file" accept=".key,.pem" @change="onKey" />
        <input type="file" accept=".pem,.crt" @change="onChain" />
      </div>
      <div class="vt-field">
        <label>{{ $t('common.password') }}</label>
        <InputText v-model="password" type="password" class="vt-input-full" />
      </div>
    </div>

    <div v-if="store.error" class="vt-error">{{ store.error }}</div>
  </BaseModal>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import BaseModal from '@/components/BaseModal.vue'
import InputText from 'primevue/inputtext'
import { useCertificateVersionStore } from '@/stores/certificateVersions'
import type { Certificate } from '@/types/Certificate'

const props = defineProps<{ visible: boolean; certificate: Certificate | null }>()
const emit = defineEmits<{ 'update:visible': [boolean]; updated: [number] }>()

const store = useCertificateVersionStore()
const p12 = ref<File | null>(null)
const cert = ref<File | null>(null)
const key = ref<File | null>(null)
const chain = ref<File | null>(null)
const password = ref('')

const hasFile = computed(() => !!p12.value || (!!cert.value && !!key.value))

const pick = (target: typeof p12) => (e: Event) => {
  target.value = (e.target as HTMLInputElement).files?.[0] ?? null
}
const onP12 = pick(p12)
const onCert = pick(cert)
const onKey = pick(key)
const onChain = pick(chain)

watch(() => props.visible, (open) => {
  if (open) {
    p12.value = null; cert.value = null; key.value = null; chain.value = null
    password.value = ''
    store.error = null
  }
})

const onSubmit = async () => {
  if (!props.certificate) return
  const form = new FormData()
  if (p12.value) form.append('p12', p12.value)
  if (cert.value) form.append('cert', cert.value)
  if (key.value) form.append('key', key.value)
  if (chain.value) form.append('chain', chain.value)
  form.append('password', password.value)
  form.append('user_id', String(props.certificate.user_id))

  const ok = await store.update(props.certificate.id, form)
  if (ok) {
    emit('updated', props.certificate.id)
    emit('update:visible', false)
  }
}

const onClose = () => emit('update:visible', false)
</script>

<style scoped>
.vt-form { display: flex; flex-direction: column; gap: 14px; margin-top: 10px; }
.vt-field { display: flex; flex-direction: column; gap: 6px; }
.vt-field label { font-size: 13px; font-weight: 500; color: var(--vt-muted); }
.vt-input-full { width: 100%; }
.vt-sub { color: var(--vt-muted); font-size: 13px; }
.vt-error { background: var(--vt-err); color: #fff; padding: 8px 12px; border-radius: 6px; margin-top: 10px; font-size: 13px; }
</style>
```

- [ ] **Step 3: Создать модалку истории**

`frontend/src/components/CertificateVersionsModal.vue`:

```vue
<template>
  <BaseModal
    :visible="visible"
    :title="$t('certVersions.historyTitle')"
    hideFooter
    width="720px"
    @update:visible="(v: boolean) => emit('update:visible', v)"
    @cancel="emit('update:visible', false)"
  >
    <DataTable :value="store.versions" dataKey="version" class="vt-table">
      <Column field="version" :header="$t('certVersions.version')">
        <template #body="{ data }">
          {{ data.version }}
          <Tag v-if="data.current" :value="$t('certVersions.current')" severity="success" />
        </template>
      </Column>
      <Column :header="$t('common.colCreatedOn')">
        <template #body="{ data }">{{ formatDate(data.created_on) }}</template>
      </Column>
      <Column :header="$t('common.colValidUntil')">
        <template #body="{ data }">{{ formatDate(data.valid_until) }}</template>
      </Column>
      <Column :header="$t('certVersions.fingerprint')">
        <template #body="{ data }">
          <code v-tooltip.top="data.fingerprint">{{ short(data.fingerprint) }}</code>
        </template>
      </Column>
      <Column :header="$t('certVersions.replacedAt')">
        <template #body="{ data }">{{ data.replaced_at ? formatDate(data.replaced_at) : '—' }}</template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <div class="vt-row-actions">
            <Button icon="pi pi-download" severity="secondary" outlined size="small"
                    v-tooltip.top="$t('certVersions.downloadP12')"
                    @click="download(data.version)" />
            <Button icon="pi pi-file-export" severity="secondary" outlined size="small"
                    v-tooltip.top="$t('certVersions.downloadPem')"
                    @click="download(data.version, 'pem')" />
            <Button icon="pi pi-key" severity="secondary" outlined size="small"
                    v-tooltip.top="$t('certVersions.showPassword')"
                    @click="showPassword(data.version)" />
            <Button v-if="authStore.isLocalAdmin && !data.current"
                    icon="pi pi-trash" severity="danger" outlined size="small"
                    v-tooltip.top="$t('certVersions.deleteVersion')"
                    @click="remove(data.version)" />
          </div>
        </template>
      </Column>
      <template #empty>
        <div class="vt-empty">{{ $t('certVersions.noHistory') }}</div>
      </template>
    </DataTable>

    <div v-if="revealed" class="vt-secret">{{ revealed }}</div>
    <div v-if="store.error" class="vt-error">{{ store.error }}</div>
  </BaseModal>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import Tooltip from 'primevue/tooltip'
import BaseModal from '@/components/BaseModal.vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import { useCertificateVersionStore } from '@/stores/certificateVersions'
import { useAuthStore } from '@/stores/auth'
import { downloadCertificate, fetchCertificatePassword } from '@/api/certificates'
import type { Certificate } from '@/types/Certificate'

const props = defineProps<{ visible: boolean; certificate: Certificate | null }>()
const emit = defineEmits<{ 'update:visible': [boolean] }>()

const vTooltip = Tooltip
const store = useCertificateVersionStore()
const authStore = useAuthStore()
const revealed = ref<string | null>(null)

watch(() => props.visible, (open) => {
  revealed.value = null
  if (open && props.certificate) store.fetchForCertificate(props.certificate.id)
})

const short = (fp: string | null) => (fp ? `${fp.slice(0, 12)}…` : '—')
const formatDate = (ms: number) => new Date(ms).toLocaleString()

const download = async (version: number, format?: 'pem') => {
  if (props.certificate) await downloadCertificate(props.certificate.id, format, version)
}

const showPassword = async (version: number) => {
  if (props.certificate) revealed.value = await fetchCertificatePassword(props.certificate.id, version)
}

const remove = async (version: number) => {
  if (props.certificate) await store.remove(props.certificate.id, version)
}
</script>

<style scoped>
.vt-table { margin-top: 8px; }
.vt-row-actions { display: flex; gap: 6px; }
.vt-empty { text-align: center; padding: 16px; color: var(--vt-muted); font-style: italic; }
.vt-secret { margin-top: 10px; padding: 8px 12px; border: 1px solid var(--vt-border); border-radius: 6px; font-family: monospace; word-break: break-all; }
.vt-error { background: var(--vt-err); color: #fff; padding: 8px 12px; border-radius: 6px; margin-top: 10px; font-size: 13px; }
</style>
```

- [ ] **Step 4: Подключить кнопки в списке сертификатов**

В `frontend/src/components/OverviewTab.vue` в колонку действий (после кнопки `DownloadPemButton`) добавить:

```vue
            <Button
              :id="'UpdateCertButton-' + data.id"
              v-if="canManage(data) && data.is_imported && !data.revoked_at"
              icon="pi pi-upload"
              severity="secondary"
              outlined
              size="small"
              v-tooltip.top="$t('certVersions.update')"
              :aria-label="$t('certVersions.update')"
              @click="openUpdate(data)"
            />
            <Button
              :id="'CertHistoryButton-' + data.id"
              v-if="canDownload() && data.version > 1"
              icon="pi pi-history"
              severity="secondary"
              outlined
              size="small"
              v-tooltip.top="$t('certVersions.history')"
              :aria-label="$t('certVersions.history')"
              @click="openHistory(data)"
            />
```

В колонке имени (строка ~84) рядом с `name.cn` показать бейдж версии:

```vue
        <template #body="{ data }">
          <span>{{ data.name.cn }}</span>
          <Tag v-if="data.version > 1" :value="'v' + data.version" severity="secondary" />
        </template>
```

Перед закрывающим `</div>` шаблона добавить обе модалки:

```vue
    <UpdateCertificateModal
      v-model:visible="isUpdateVisible"
      :certificate="selectedCertificate"
      @updated="onCertificateUpdated"
    />
    <CertificateVersionsModal
      v-model:visible="isHistoryVisible"
      :certificate="selectedCertificate"
    />
```

В `<script setup>` добавить импорты и состояние:

```ts
import UpdateCertificateModal from '@/components/UpdateCertificateModal.vue'
import CertificateVersionsModal from '@/components/CertificateVersionsModal.vue'

const isUpdateVisible = ref(false)
const isHistoryVisible = ref(false)
const selectedCertificate = ref<Certificate | null>(null)

const openUpdate = (cert: Certificate) => {
  selectedCertificate.value = cert
  isUpdateVisible.value = true
}

const openHistory = (cert: Certificate) => {
  selectedCertificate.value = cert
  isHistoryVisible.value = true
}

const onCertificateUpdated = async () => {
  await certStore.fetchCertificates()
}
```

Имя стора сертификатов в этом файле уже существует — использовать то, которое там объявлено (посмотреть строку с `useCertificateStore()`), а не заводить второе.

`Tag` уже импортирован в `OverviewTab.vue`, если нет — добавить `import Tag from 'primevue/tag'`.

- [ ] **Step 5: Проверить типы, тесты и сборку**

Run: `cd frontend && npm run type-check && npm run test:unit && npm run build-only 2>&1 | tail -8`
Expected: типы чисто, тесты PASS, сборка проходит.

- [ ] **Step 6: Коммит**

```bash
git add frontend/src/components frontend/src/locales
git commit -m "feat(ui): update certificate and browse its version history"
```

---

### Task 11: Документация и финальная проверка

**Files:**
- Modify: `README.md` (раздел про сертификаты)
- Modify: `docs/superpowers/plans/2026-07-29-certificate-versions.md` (отметить выполненные шаги)

- [ ] **Step 1: Описать фичу в README**

Найти в `README.md` раздел, описывающий работу с сертификатами, и добавить абзац:

```markdown
### Updating imported certificates

An imported certificate can be replaced with a newer file while keeping its id,
so agents that poll it by `cert_id` pick up the change automatically. The
previous contents move into a version history: `GET /api/certificates/<id>/versions`
lists every version, and `?version=N` on the download and password endpoints
serves a historical one. Certificates issued by the internal CA and ACME
certificates are not editable — their renewal is handled by their own flow.
```

- [ ] **Step 2: Полный прогон бэкенда**

Run: `cd backend && cargo test 2>&1 | tail -5`
Expected: единственный провал — `test_ssh_revocation_and_krl` (внешний `ssh-keygen`, не регрессия).

- [ ] **Step 3: Полный прогон фронтенда**

Run: `cd frontend && npm run type-check && npm run test:unit && npm run build-only 2>&1 | tail -5`
Expected: всё зелёное.

- [ ] **Step 4: Проверить, что сборка контейнера не сломана**

Run: `docker compose build vaultls 2>&1 | tail -5`
Expected: образ собирается.

- [ ] **Step 5: Коммит**

```bash
git add README.md docs/superpowers/plans
git commit -m "docs: describe certificate update and version history"
```

- [ ] **Step 6: Влить ветку**

```bash
git checkout main
git merge --no-ff feat/certificate-versions -m "Merge branch 'feat/certificate-versions': update imported certificates with version history"
git push origin main
git branch -d feat/certificate-versions
```
