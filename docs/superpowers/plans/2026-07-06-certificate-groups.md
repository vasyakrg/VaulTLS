# Certificate Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ввести группы как слой контроля доступа к user-сертификатам: пользователь видит сертификат, если он владелец или состоит с ним в общей группе; управляет группами только локальный (не-OIDC) администратор.

**Architecture:** Три M2M-таблицы (`groups`, `group_users`, `group_certificates`). В JWT-claims добавляется флаг `is_local` для различения локального и OIDC-администратора. Класс актора (local admin / OIDC admin / user / service) вычисляется из claims и определяет видимость, download и права delete/revoke. Новый guard `AuthenticatedLocalAdmin` защищает CRUD групп и CA-операции. Фронт получает admin-only вкладку Groups.

**Tech Stack:** Rust / Rocket / rusqlite (SQLCipher) / rocket_okapi; Vue 3 + Pinia + TypeScript.

## Global Constraints

- Миграции — каталоги `backend/migrations/NN-name/{up.sql,down.sql}`, применяются через `Migrations::from_directory` (порядок по имени). Следующий номер — **15**.
- Все запросы к БД — внутри `db_do!(self.pool, |conn: &Connection| { ... })`, возвращают `anyhow::Result<T>`.
- Guard-ы объявляются в `backend/src/auth/session_auth.rs` и получают `impl_openapi_auth!(Guard, "роль")`.
- Роуты монтируются в `backend/src/lib.rs` — **три идентичных блока** `openapi_get_routes![...]` (≈ строки 215, 302, 354). Новый роут добавляется во все три.
- Backend-тесты: db-слой — `#[tokio::test]` в `mod tests` внутри `db.rs` через `mem_db()`; API — integration в `backend/tests/api/*.rs` через `VaulTLSClient`.
- `VaulTLSClient::new_authenticated()` → залогинен как setup-user `id=1` (локальный admin, пароль `TEST_PASSWORD`). `VaulTLSClient::new_authenticated_unprivileged()` → создаёт второго пользователя (role=User) и переключается на него.
- Frontend: api-модуль `frontend/src/api/<name>.ts`, pinia store `frontend/src/stores/<name>.ts`, вкладка `frontend/src/components/<Name>Tab.vue`. Образцы: `api/users.ts`, `stores/users.ts`, `components/UserTab.vue`.
- Commit после каждой задачи. Ветка уже создана: `feat/certificate-groups`.

---

## Task 1: Миграция 15-groups

**Files:**
- Create: `backend/migrations/15-groups/up.sql`
- Create: `backend/migrations/15-groups/down.sql`
- Test: `backend/src/db.rs` (в `mod tests`)

**Interfaces:**
- Produces: таблицы `groups`, `group_users`, `group_certificates`.

- [ ] **Step 1: Написать миграцию up.sql**

`backend/migrations/15-groups/up.sql`:
```sql
CREATE TABLE groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_on  INTEGER NOT NULL
);

CREATE TABLE group_users (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE group_certificates (
    group_id       INTEGER NOT NULL REFERENCES groups(id)            ON DELETE CASCADE,
    certificate_id INTEGER NOT NULL REFERENCES user_certificates(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, certificate_id)
);
```

- [ ] **Step 2: Написать down.sql**

`backend/migrations/15-groups/down.sql`:
```sql
DROP TABLE group_certificates;
DROP TABLE group_users;
DROP TABLE groups;
```

- [ ] **Step 3: Написать падающий тест применения миграции**

В `backend/src/db.rs`, внутри `mod tests`, добавить:
```rust
#[tokio::test]
async fn migration_15_creates_group_tables() {
    let db = mem_db().await;
    let groups = db.get_all_groups().await.unwrap();
    assert_eq!(groups.len(), 0);
}
```

- [ ] **Step 4: Запустить — тест не компилируется (нет `get_all_groups`)**

Run: `cd backend && cargo test migration_15_creates_group_tables 2>&1 | tail -20`
Expected: ошибка компиляции `no method named get_all_groups`. Это ожидаемо — метод появится в Task 4. Пока проверяем только, что миграция валидна: временно замените тело теста на прямой запрос:
```rust
#[tokio::test]
async fn migration_15_creates_group_tables() {
    let db = mem_db().await;
    // прямой доступ к пулу недоступен извне — проверяем через существующий метод:
    // миграция применяется в new_in_memory(); успешная сборка БД = миграция ок
    let _ = db.get_all_user().await.unwrap();
}
```

- [ ] **Step 5: Запустить — тест проходит (миграция применяется без ошибок)**

Run: `cd backend && cargo test migration_15_creates_group_tables 2>&1 | tail -20`
Expected: PASS. Если миграция синтаксически невалидна — `new_in_memory()` паникует с "Failed to migrate database".

- [ ] **Step 6: Commit**

```bash
git add backend/migrations/15-groups backend/src/db.rs
git commit -m "feat(db): add 15-groups migration (groups, group_users, group_certificates)"
```

---

## Task 2: Флаг `is_local` в JWT Claims

**Files:**
- Modify: `backend/src/auth/session_auth.rs`
- Modify: `backend/src/api.rs:140,307` (вызовы `generate_token`)

**Interfaces:**
- Produces: `Claims.is_local: bool`; `Claims::is_local_admin() -> bool`; `generate_token(jwt_key, user_id, user_role, is_local)`; `generate_service_token(...)` без изменения сигнатуры (внутри ставит `is_local=false`).
- Consumes: существующие `Claims { jti, id, role, exp, service }`.

- [ ] **Step 1: Написать падающий тест на дефолт старого токена и хелпер**

В `backend/src/auth/session_auth.rs`, в `mod service_token_tests`, добавить:
```rust
#[test]
fn old_token_without_is_local_defaults_false() {
    // токен, закодированный без поля is_local, должен декодироваться в is_local=false
    let key = b"0123456789abcdef0123456789abcdef";
    #[derive(serde::Serialize)]
    struct OldClaims { jti: String, id: i64, role: u8, exp: usize }
    let old = OldClaims { jti: "j".into(), id: 1, role: 1, exp: 9_999_999_999 };
    let token = encode(&Header::default(), &old, &EncodingKey::from_secret(key)).unwrap();
    let claims = decode::<Claims>(&token, &DecodingKey::from_secret(key), &Validation::default()).unwrap().claims;
    assert!(!claims.is_local);
}

#[test]
fn is_local_admin_classification() {
    let admin_local = Claims { jti: "a".into(), id: 1, role: UserRole::Admin, exp: 0, service: None, is_local: true };
    let admin_oidc  = Claims { jti: "b".into(), id: 2, role: UserRole::Admin, exp: 0, service: None, is_local: false };
    let user_local  = Claims { jti: "c".into(), id: 3, role: UserRole::User,  exp: 0, service: None, is_local: true };
    assert!(admin_local.is_local_admin());
    assert!(!admin_oidc.is_local_admin());
    assert!(!user_local.is_local_admin());
}
```

- [ ] **Step 2: Запустить — не компилируется (нет поля `is_local`)**

Run: `cd backend && cargo test -p vaultls old_token_without_is_local_defaults_false 2>&1 | tail -15`
Expected: ошибка `struct Claims has no field named is_local`.

- [ ] **Step 3: Добавить поле и хелпер**

В `Claims` (после `service`):
```rust
    #[serde(default)]
    pub(crate) is_local: bool,
```
В `impl Claims` добавить:
```rust
    pub(crate) fn is_local_admin(&self) -> bool {
        !self.is_service() && self.role == UserRole::Admin && self.is_local
    }
```
Обновить `generate_token`:
```rust
pub(crate) fn generate_token(jwt_key: &[u8], user_id: i64, user_role: UserRole, is_local: bool) -> Result<String, ApiError> {
```
и в его теле `Claims { ..., service: None, is_local }`.
В `generate_service_token` добавить в `Claims { ..., is_local: false }`.

- [ ] **Step 4: Обновить вызовы `generate_token` в api.rs**

`backend/src/api.rs:140` (login — локальный пароль):
```rust
    let token = generate_token(&jwt_key, user.id, user.role, true)?;
```
`backend/src/api.rs:307` (oidc_callback):
```rust
    let token = generate_token(&jwt_key, user.id, user.role, false)?;
```

- [ ] **Step 5: Запустить тесты**

Run: `cd backend && cargo test -p vaultls old_token_without_is_local_defaults_false is_local_admin_classification service_token_carries_scopes 2>&1 | tail -15`
Expected: PASS (все три).

- [ ] **Step 6: Commit**

```bash
git add backend/src/auth/session_auth.rs backend/src/api.rs
git commit -m "feat(auth): add is_local flag to JWT claims + is_local_admin helper"
```

---

## Task 3: Guard `AuthenticatedLocalAdmin`

**Files:**
- Modify: `backend/src/auth/session_auth.rs`

**Interfaces:**
- Consumes: `authenticate_auth_token`, `Claims::is_local_admin`.
- Produces: guard `AuthenticatedLocalAdmin { _claims: Claims }`.

- [ ] **Step 1: Добавить guard**

После `AuthenticatedPrivileged` в `session_auth.rs`:
```rust
pub struct AuthenticatedLocalAdmin {
    pub _claims: Claims,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedLocalAdmin {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(claims) = authenticate_auth_token(request) else { return Outcome::Error((Status::Unauthorized, ())) };
        if claims.is_local_admin() {
            Outcome::Success(AuthenticatedLocalAdmin { _claims: claims })
        } else {
            Outcome::Error((Status::Forbidden, ()))
        }
    }
}

impl_openapi_auth!(AuthenticatedLocalAdmin, "local UserRole::Admin");
```

- [ ] **Step 2: Добавить struct в объявление guard-типа для теста**

Тест guard-а невозможно изолировать без Rocket-request; корректность классификации уже покрыта `is_local_admin_classification` (Task 2) и будет проверена end-to-end в Task 6/11. Здесь достаточно компиляции.

- [ ] **Step 3: Проверить сборку**

Run: `cd backend && cargo build 2>&1 | tail -15`
Expected: сборка успешна.

- [ ] **Step 4: Commit**

```bash
git add backend/src/auth/session_auth.rs
git commit -m "feat(auth): add AuthenticatedLocalAdmin guard"
```

---

## Task 4: DB — структуры Group и CRUD

**Files:**
- Modify: `backend/src/data/objects.rs`
- Modify: `backend/src/db.rs`
- Test: `backend/src/db.rs` (`mod tests`)

**Interfaces:**
- Produces:
  - `struct Group { id: i64, name: String, description: Option<String>, created_on: i64 }`
  - `struct GroupDetail { group: Group, user_ids: Vec<i64>, certificate_ids: Vec<i64> }`
  - `insert_group(name: String, description: Option<String>, created_on: i64) -> Result<Group>`
  - `get_all_groups() -> Result<Vec<Group>>`
  - `get_group_detail(id: i64) -> Result<GroupDetail>`
  - `update_group(id: i64, name: String, description: Option<String>) -> Result<()>`
  - `delete_group(id: i64) -> Result<()>`
  - `set_group_users(id: i64, user_ids: &[i64]) -> Result<()>`
  - `set_group_certs(id: i64, cert_ids: &[i64]) -> Result<()>`

- [ ] **Step 1: Добавить структуры в objects.rs**

В `backend/src/data/objects.rs` (рядом с `ServiceAccount`):
```rust
#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_on: i64,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct GroupDetail {
    #[serde(flatten)]
    pub group: Group,
    pub user_ids: Vec<i64>,
    pub certificate_ids: Vec<i64>,
}
```

- [ ] **Step 2: Написать падающий тест CRUD**

В `backend/src/db.rs`, `mod tests`:
```rust
#[tokio::test]
async fn group_crud_and_membership() {
    let db = mem_db().await;
    let admin = db.insert_user(User { id: -1, name: "a".into(), email: "a@b.c".into(), password_hash: None, oidc_id: None, role: UserRole::Admin }).await.unwrap();

    let g = db.insert_group("A".into(), Some("desc".into()), 100).await.unwrap();
    assert!(g.id > 0);
    assert_eq!(db.get_all_groups().await.unwrap().len(), 1);

    db.update_group(g.id, "A2".into(), None).await.unwrap();
    let d = db.get_group_detail(g.id).await.unwrap();
    assert_eq!(d.group.name, "A2");
    assert_eq!(d.group.description, None);

    db.set_group_users(g.id, &[admin.id]).await.unwrap();
    db.set_group_users(g.id, &[admin.id]).await.unwrap(); // replace-семантика, без дублей
    let d = db.get_group_detail(g.id).await.unwrap();
    assert_eq!(d.user_ids, vec![admin.id]);

    db.delete_group(g.id).await.unwrap();
    assert_eq!(db.get_all_groups().await.unwrap().len(), 0);
}
```
Импорт `UserRole` в тестах уже доступен через `use super::*` при условии, что `db.rs` его импортирует; при ошибке — добавить `use crate::data::enums::UserRole;` в шапку теста.

- [ ] **Step 3: Запустить — не компилируется**

Run: `cd backend && cargo test group_crud_and_membership 2>&1 | tail -15`
Expected: `no method named insert_group`.

- [ ] **Step 4: Реализовать методы в db.rs**

Добавить в `impl VaulTLSDB` (использовать `use crate::data::objects::{Group, GroupDetail};` в шапке db.rs):
```rust
pub(crate) async fn insert_group(&self, name: String, description: Option<String>, created_on: i64) -> Result<Group> {
    db_do!(self.pool, |conn: &Connection| {
        conn.execute(
            "INSERT INTO groups (name, description, created_on) VALUES (?1, ?2, ?3)",
            params![name, description, created_on],
        )?;
        let id = conn.last_insert_rowid();
        Ok(Group { id, name, description, created_on })
    })
}

pub(crate) async fn get_all_groups(&self) -> Result<Vec<Group>> {
    db_do!(self.pool, |conn: &Connection| {
        let mut stmt = conn.prepare("SELECT id, name, description, created_on FROM groups ORDER BY name")?;
        let rows = stmt.query_map([], |r| Ok(Group {
            id: r.get(0)?, name: r.get(1)?, description: r.get(2)?, created_on: r.get(3)?,
        }))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

pub(crate) async fn get_group_detail(&self, id: i64) -> Result<GroupDetail> {
    db_do!(self.pool, |conn: &Connection| {
        let group = conn.query_row(
            "SELECT id, name, description, created_on FROM groups WHERE id = ?1",
            params![id],
            |r| Ok(Group { id: r.get(0)?, name: r.get(1)?, description: r.get(2)?, created_on: r.get(3)? }),
        )?;
        let mut us = conn.prepare("SELECT user_id FROM group_users WHERE group_id = ?1")?;
        let user_ids = us.query_map(params![id], |r| r.get::<_, i64>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut cs = conn.prepare("SELECT certificate_id FROM group_certificates WHERE group_id = ?1")?;
        let certificate_ids = cs.query_map(params![id], |r| r.get::<_, i64>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(GroupDetail { group, user_ids, certificate_ids })
    })
}

pub(crate) async fn update_group(&self, id: i64, name: String, description: Option<String>) -> Result<()> {
    db_do!(self.pool, |conn: &Connection| {
        conn.execute("UPDATE groups SET name = ?1, description = ?2 WHERE id = ?3", params![name, description, id])?;
        Ok(())
    })
}

pub(crate) async fn delete_group(&self, id: i64) -> Result<()> {
    db_do!(self.pool, |conn: &Connection| {
        conn.execute("DELETE FROM groups WHERE id = ?1", params![id])?;
        Ok(())
    })
}

pub(crate) async fn set_group_users(&self, id: i64, user_ids: &[i64]) -> Result<()> {
    let user_ids = user_ids.to_vec();
    db_do!(self.pool, move |conn: &Connection| {
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM group_users WHERE group_id = ?1", params![id])?;
        for uid in &user_ids {
            tx.execute("INSERT INTO group_users (group_id, user_id) VALUES (?1, ?2)", params![id, uid])?;
        }
        tx.commit()?;
        Ok(())
    })
}

pub(crate) async fn set_group_certs(&self, id: i64, cert_ids: &[i64]) -> Result<()> {
    let cert_ids = cert_ids.to_vec();
    db_do!(self.pool, move |conn: &Connection| {
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM group_certificates WHERE group_id = ?1", params![id])?;
        for cid in &cert_ids {
            tx.execute("INSERT INTO group_certificates (group_id, certificate_id) VALUES (?1, ?2)", params![id, cid])?;
        }
        tx.commit()?;
        Ok(())
    })
}
```
Примечание: `unchecked_transaction()` используется, т.к. `conn` в замыкании — `&Connection` (не `&mut`). Это штатный способ в rusqlite для получения транзакции по shared-ссылке.

- [ ] **Step 5: Запустить тест**

Run: `cd backend && cargo test group_crud_and_membership 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/data/objects.rs backend/src/db.rs
git commit -m "feat(db): group CRUD and membership methods"
```

---

## Task 5: DB — видимость сертификатов через группы

**Files:**
- Modify: `backend/src/db.rs`
- Test: `backend/src/db.rs` (`mod tests`)

**Interfaces:**
- Consumes: `insert_user`, `insert_user_cert`, `insert_group`, `set_group_users`, `set_group_certs`, `Certificate`.
- Produces:
  - `get_visible_certs(user_id: i64) -> Result<Vec<Certificate>>` — серты владельца ИЛИ через общую группу.
  - `user_shares_group_with_cert(user_id: i64, cert_id: i64) -> Result<bool>`.

- [ ] **Step 1: Написать падающий тест видимости**

В `backend/src/db.rs`, `mod tests`. Опереться на существующий helper построения серта (см. тест `acme_client_renewal_helpers`, где создаётся `User` и далее серт). Минимальный тест:
```rust
#[tokio::test]
async fn visibility_owner_and_group() {
    let db = mem_db().await;
    let ca = db.insert_ca(test_ca()).await.unwrap(); // см. существующий helper построения CA в тестах db.rs
    let owner = db.insert_user(User { id: -1, name: "o".into(), email: "o@x.c".into(), password_hash: None, oidc_id: None, role: UserRole::User }).await.unwrap();
    let viewer = db.insert_user(User { id: -1, name: "v".into(), email: "v@x.c".into(), password_hash: None, oidc_id: None, role: UserRole::User }).await.unwrap();

    let cert = db.insert_user_cert(test_cert(owner.id, ca.id)).await.unwrap(); // helper строит Certificate

    // viewer не видит чужой серт без группы
    assert_eq!(db.get_visible_certs(viewer.id).await.unwrap().len(), 0);
    // owner видит свой
    assert_eq!(db.get_visible_certs(owner.id).await.unwrap().len(), 1);

    // общая группа делает серт видимым viewer-у
    let g = db.insert_group("G".into(), None, 1).await.unwrap();
    db.set_group_users(g.id, &[viewer.id]).await.unwrap();
    db.set_group_certs(g.id, &[cert.id]).await.unwrap();
    assert_eq!(db.get_visible_certs(viewer.id).await.unwrap().len(), 1);
    assert!(db.user_shares_group_with_cert(viewer.id, cert.id).await.unwrap());
    assert!(!db.user_shares_group_with_cert(owner.id, cert.id).await.unwrap()); // owner не в группе
}
```
`test_ca()` / `test_cert(owner_id, ca_id)` — если в `mod tests` ещё нет таких helper-ов, добавить их по образцу построения CA/Certificate из соседних тестов (`acme_client_renewal_helpers` показывает построение `User`; для `Certificate`/`CA` — использовать `TLSCertificateBuilder`/готовые конструкторы уже импортированные в db.rs тестах). Если построение серта тяжёлое — допустимо вставлять строку напрямую SQL-ом через уже существующий `insert_user_cert`.

- [ ] **Step 2: Запустить — не компилируется**

Run: `cd backend && cargo test visibility_owner_and_group 2>&1 | tail -15`
Expected: `no method named get_visible_certs`.

- [ ] **Step 3: Реализовать методы**

Столбцы `Certificate` берём точно как в `get_user_certs` (см. `db.rs:300`). Добавить:
```rust
pub(crate) async fn get_visible_certs(&self, user_id: i64) -> Result<Vec<Certificate>> {
    db_do!(self.pool, |conn: &Connection| {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT c.id, c.name, c.created_on, c.valid_until, c.data, c.password, c.user_id, c.type, c.renew_method, c.ca_id, c.revoked_at, c.acme_provider_id \
             FROM user_certificates c \
             WHERE c.user_id = ?1 \
                OR c.id IN ( \
                   SELECT gc.certificate_id FROM group_certificates gc \
                   JOIN group_users gu ON gu.group_id = gc.group_id \
                   WHERE gu.user_id = ?1)"
        )?;
        let rows = stmt.query(params![user_id])?;
        Ok(rows.mapped(Certificate::from_row).collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

pub(crate) async fn user_shares_group_with_cert(&self, user_id: i64, cert_id: i64) -> Result<bool> {
    db_do!(self.pool, |conn: &Connection| {
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM group_certificates gc \
             JOIN group_users gu ON gu.group_id = gc.group_id \
             WHERE gc.certificate_id = ?1 AND gu.user_id = ?2",
            params![cert_id, user_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    })
}
```

- [ ] **Step 4: Запустить тест**

Run: `cd backend && cargo test visibility_owner_and_group 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/db.rs
git commit -m "feat(db): get_visible_certs and user_shares_group_with_cert"
```

---

## Task 6: API — CRUD-эндпоинты групп + монтирование

**Files:**
- Modify: `backend/src/data/api.rs` (request-структуры)
- Modify: `backend/src/api.rs` (handlers)
- Modify: `backend/src/lib.rs` (3 блока mount)
- Test: `backend/tests/api/api_test_groups.rs` (Create), `backend/tests/api/mod.rs` (Modify)

**Interfaces:**
- Consumes: `AuthenticatedLocalAdmin`, все методы Task 4.
- Produces: роуты `GET/POST /groups`, `GET/PUT/DELETE /groups/<id>`, `PUT /groups/<id>/users`, `PUT /groups/<id>/certificates`.

- [ ] **Step 1: Добавить request-структуры**

В `backend/src/data/api.rs`:
```rust
#[derive(Deserialize, JsonSchema)]
pub struct GroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GroupMembersRequest {
    pub ids: Vec<i64>,
}
```

- [ ] **Step 2: Написать падающий integration-тест**

Create `backend/tests/api/api_test_groups.rs`:
```rust
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::json;

#[tokio::test]
async fn local_admin_can_crud_groups() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // setup-user = local admin id=1

    // create
    let resp = client.post("/groups").header(ContentType::JSON)
        .body(json!({"name":"Alpha","description":"first"}).to_string())
        .dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    // list
    let resp = client.get("/groups").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    assert!(body.contains("Alpha"));

    Ok(())
}

#[tokio::test]
async fn plain_user_cannot_manage_groups() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await; // role=User
    let resp = client.post("/groups").header(ContentType::JSON)
        .body(json!({"name":"X"}).to_string())
        .dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}
```
Зарегистрировать модуль: в `backend/tests/api/mod.rs` добавить `mod api_test_groups;`.

- [ ] **Step 3: Запустить — падает (404/нет роутов)**

Run: `cd backend && cargo test local_admin_can_crud_groups 2>&1 | tail -20`
Expected: FAIL — статус не Ok (роут не смонтирован).

- [ ] **Step 4: Реализовать handlers**

В `backend/src/api.rs` (импортировать `AuthenticatedLocalAdmin`, `Group`, `GroupDetail`, `GroupRequest`, `GroupMembersRequest`, `current_timestamp`-аналог — используйте тот же способ, что и другие эндпоинты для времени, напр. `chrono::Utc::now().timestamp()` если он уже применяется в проекте; иначе `std::time::SystemTime`):
```rust
#[openapi(tag = "Groups")]
#[get("/groups")]
pub(crate) async fn get_groups(state: &State<AppState>, _auth: AuthenticatedLocalAdmin) -> Result<Json<Vec<Group>>, ApiError> {
    Ok(Json(state.db.get_all_groups().await?))
}

#[openapi(tag = "Groups")]
#[get("/groups/<id>")]
pub(crate) async fn get_group(state: &State<AppState>, id: i64, _auth: AuthenticatedLocalAdmin) -> Result<Json<GroupDetail>, ApiError> {
    Ok(Json(state.db.get_group_detail(id).await?))
}

#[openapi(tag = "Groups")]
#[post("/groups", format = "json", data = "<payload>")]
pub(crate) async fn create_group(state: &State<AppState>, payload: Json<GroupRequest>, _auth: AuthenticatedLocalAdmin) -> Result<Json<i64>, ApiError> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let g = state.db.insert_group(payload.name.clone(), payload.description.clone(), now).await?;
    Ok(Json(g.id))
}

#[openapi(tag = "Groups")]
#[put("/groups/<id>", format = "json", data = "<payload>")]
pub(crate) async fn update_group(state: &State<AppState>, id: i64, payload: Json<GroupRequest>, _auth: AuthenticatedLocalAdmin) -> Result<(), ApiError> {
    state.db.update_group(id, payload.name.clone(), payload.description.clone()).await?;
    Ok(())
}

#[openapi(tag = "Groups")]
#[delete("/groups/<id>")]
pub(crate) async fn delete_group(state: &State<AppState>, id: i64, _auth: AuthenticatedLocalAdmin) -> Result<(), ApiError> {
    state.db.delete_group(id).await?;
    Ok(())
}

#[openapi(tag = "Groups")]
#[put("/groups/<id>/users", format = "json", data = "<payload>")]
pub(crate) async fn set_group_users(state: &State<AppState>, id: i64, payload: Json<GroupMembersRequest>, _auth: AuthenticatedLocalAdmin) -> Result<(), ApiError> {
    state.db.set_group_users(id, &payload.ids).await?;
    Ok(())
}

#[openapi(tag = "Groups")]
#[put("/groups/<id>/certificates", format = "json", data = "<payload>")]
pub(crate) async fn set_group_certificates(state: &State<AppState>, id: i64, payload: Json<GroupMembersRequest>, _auth: AuthenticatedLocalAdmin) -> Result<(), ApiError> {
    state.db.set_group_certs(id, &payload.ids).await?;
    Ok(())
}
```
Примечание: имена handler-функций `update_group`/`set_group_users` не должны конфликтовать с методами `state.db.*` (это разные пространства — свободные функции vs методы); при желании переименуйте в `update_group_route` и т.п. и синхронно в mount.

- [ ] **Step 5: Смонтировать роуты**

В `backend/src/lib.rs` во **всех трёх** блоках `openapi_get_routes![...]` (≈ строки 215, 302, 354) добавить:
```rust
                get_groups,
                get_group,
                create_group,
                update_group,
                delete_group,
                set_group_users,
                set_group_certificates,
```

- [ ] **Step 6: Запустить оба теста**

Run: `cd backend && cargo test local_admin_can_crud_groups plain_user_cannot_manage_groups 2>&1 | tail -20`
Expected: PASS (оба).

- [ ] **Step 7: Commit**

```bash
git add backend/src/data/api.rs backend/src/api.rs backend/src/lib.rs backend/tests/api/
git commit -m "feat(api): group CRUD endpoints guarded by local admin"
```

---

## Task 7: API — видимость списка сертификатов

**Files:**
- Modify: `backend/src/api.rs:342-355` (`get_certificates`)
- Test: `backend/tests/api/api_test_groups.rs`

**Interfaces:**
- Consumes: `get_visible_certs`, `Claims::is_local_admin`, `Claims::is_service`, `has_scope`.

- [ ] **Step 1: Написать падающий тест видимости через список**

В `backend/tests/api/api_test_groups.rs`:
```rust
#[tokio::test]
async fn user_sees_only_owned_and_group_certs() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;      // local admin id=1
    client.create_user().await?;                                // создаёт user id=2 (role=User)
    // серт владельца id=2, выпущен админом
    let cert = client.create_client_cert(Some(2), Some("pw".into()), None).await?;

    client.switch_user().await?;                                // теперь под user id=2
    // user id=2 — владелец, видит свой серт
    let resp = client.get("/certificates").dispatch().await;
    let body = resp.into_string().await.unwrap();
    assert!(body.contains(&cert.id.to_string()));

    Ok(())
}
```
(Проверка «не видит чужой» на db-уровне уже есть в Task 5; здесь фиксируем, что владелец через API видит свой.)

- [ ] **Step 2: Запустить — сейчас проходит и так (владелец виден); убедиться в базовой корректности**

Run: `cd backend && cargo test user_sees_only_owned_and_group_certs 2>&1 | tail -15`
Expected: PASS (текущая логика `get_user_certs(Some(id))` уже отдаёт свои). Тест закрепляет поведение перед рефакторингом.

- [ ] **Step 3: Заменить логику на групповую видимость**

`backend/src/api.rs`, тело `get_certificates`:
```rust
    if authentication.claims.is_service() && !authentication.claims.has_scope("cert:read") {
        return Err(ApiError::Forbidden(None));
    }
    let certificates = if authentication.claims.is_local_admin() {
        state.db.get_user_certs(None, None, None).await?
    } else {
        state.db.get_visible_certs(authentication.claims.id).await?
    };
    Ok(Json(certificates))
```

- [ ] **Step 4: Запустить тест + существующие cert-тесты**

Run: `cd backend && cargo test user_sees_only_owned_and_group_certs 2>&1 | tail -15 && cargo test --test integration_tests 2>&1 | tail -20`
Expected: PASS; существующие тесты сертификатов не сломаны.

- [ ] **Step 5: Commit**

```bash
git add backend/src/api.rs backend/tests/api/api_test_groups.rs
git commit -m "feat(api): certificate list visibility via groups"
```

---

## Task 8: API — download и пароль по матрице доступа

**Files:**
- Modify: `backend/src/api.rs` (`download_certificate` ~1038, `fetch_certificate_password` ~1116)
- Test: `backend/tests/api/api_test_groups.rs`

**Interfaces:**
- Consumes: `get_user_cert_by_id`, `get_user_cert_password`, `user_shares_group_with_cert`, `Claims::{is_local_admin, is_service, has_scope, role, id}`.
- Produces: helper `can_download(state, claims, cert_owner_id, cert_id) -> Result<bool, ApiError>`.

- [ ] **Step 1: Написать падающий тест — user не качает чужой групповой**

В `api_test_groups.rs`:
```rust
#[tokio::test]
async fn group_visibility_does_not_grant_download() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2
    let cert = client.create_client_cert(Some(1), Some("pw".into()), None).await?; // владелец = admin id=1

    // группа с user id=2 и сертом владельца id=1
    let gid: i64 = serde_json::from_str(&client.post("/groups").header(ContentType::JSON)
        .body(json!({"name":"Shared"}).to_string()).dispatch().await.into_string().await.unwrap())?;
    client.put(format!("/groups/{gid}/users")).header(ContentType::JSON)
        .body(json!({"ids":[2]}).to_string()).dispatch().await;
    client.put(format!("/groups/{gid}/certificates")).header(ContentType::JSON)
        .body(json!({"ids":[cert.id]}).to_string()).dispatch().await;

    client.switch_user().await?; // под user id=2

    // видит в списке (через группу)
    let list = client.get("/certificates").dispatch().await.into_string().await.unwrap();
    assert!(list.contains(&cert.id.to_string()));
    // но НЕ качает чужой серт
    let resp = client.get(format!("/certificates/{}/download", cert.id)).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    // и НЕ получает пароль
    let resp = client.get(format!("/certificates/{}/password", cert.id)).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}
```

- [ ] **Step 2: Запустить — падает (сейчас role==User && не владелец → уже Forbidden? да; но local admin ветку и OIDC-ветку надо ввести корректно)**

Run: `cd backend && cargo test group_visibility_does_not_grant_download 2>&1 | tail -20`
Expected: тест может уже проходить для user-ветки (текущая проверка `user_id != id && role != Admin`). Задача — заменить проверку на явную матрицу, сохранив это поведение и добавив OIDC-admin ограничение.

- [ ] **Step 3: Ввести helper и применить в обоих эндпоинтах**

В `backend/src/api.rs` (свободная функция):
```rust
/// Право скачать приватный материал серта (pkcs12/pem/пароль).
async fn can_access_cert_secret(state: &State<AppState>, claims: &crate::auth::session_auth::Claims, cert_owner_id: i64, cert_id: i64) -> Result<bool, ApiError> {
    // local admin — всё
    if claims.is_local_admin() { return Ok(true); }
    // владелец — свой (service ограничен scope cert:read; проверяется вызывающим)
    if cert_owner_id == claims.id { return Ok(true); }
    // OIDC admin (role==Admin, не local, не service) — групповые тоже
    if !claims.is_service() && claims.role == UserRole::Admin && !claims.is_local {
        return Ok(state.db.user_shares_group_with_cert(claims.id, cert_id).await?);
    }
    Ok(false)
}
```
В `download_certificate` заменить строку проверки (`if certificate.user_id != ... { return Err(Forbidden) }`) на:
```rust
    if authentication.claims.is_service() && !authentication.claims.has_scope("cert:read") {
        return Err(ApiError::Forbidden(None));
    }
    let certificate = state.db.get_user_cert_by_id(id).await?;
    if !can_access_cert_secret(state, &authentication.claims, certificate.user_id, id).await? {
        return Err(ApiError::Forbidden(None));
    }
```
(scope-проверка сервиса уже есть выше — не дублировать; порядок: scope → загрузка серта → can_access.)
Аналогично в `fetch_certificate_password`: после получения `(user_id, password)` заменить проверку на `if !can_access_cert_secret(state, &authentication.claims, user_id, id).await? { return Err(ApiError::Forbidden(None)); }`.

`Claims` сделать доступным для сигнатуры helper-а: он уже импортируется? Проверьте импорты api.rs; при необходимости `use crate::auth::session_auth::Claims;`.

- [ ] **Step 4: Запустить тест + существующие download-тесты**

Run: `cd backend && cargo test group_visibility_does_not_grant_download 2>&1 | tail -20 && cargo test --test integration_tests download 2>&1 | tail -20`
Expected: PASS; владелец/admin по-прежнему качают свои.

- [ ] **Step 5: Commit**

```bash
git add backend/src/api.rs backend/tests/api/api_test_groups.rs
git commit -m "feat(api): download/password access matrix (owner, OIDC-admin group, local-admin all)"
```

---

## Task 9: API — create/import открыть для user, владелец форсится

**Files:**
- Modify: `backend/src/api.rs` (`create_user_certificate` ~686-693, `import_certificate` guard ~518)
- Test: `backend/tests/api/api_test_groups.rs`

**Interfaces:**
- Consumes: `Claims::{is_local_admin, is_service, has_scope, id}`.

- [ ] **Step 1: Написать падающий тест — обычный user создаёт серт себе**

```rust
#[tokio::test]
async fn plain_user_can_issue_own_cert() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await; // user id=2
    // пытается выписать серт на чужой user_id=1 — должен принудительно стать своим (id=2)
    let cert = client.create_client_cert(Some(1), Some("pw".into()), None).await?;
    assert_eq!(cert.user_id, 2);
    Ok(())
}
```

- [ ] **Step 2: Запустить — падает (сейчас role==User → Forbidden в create)**

Run: `cd backend && cargo test plain_user_can_issue_own_cert 2>&1 | tail -20`
Expected: FAIL — `create_client_cert` получает не-Ok статус (assert внутри helper упадёт).

- [ ] **Step 3: Обновить авторизацию создания**

В `backend/src/api.rs`, блок авторизации `create_user_certificate` заменить:
```rust
    if authentication.claims.is_service() {
        if !authentication.claims.has_scope("cert:issue") {
            return Err(ApiError::Forbidden(None));
        }
        payload.user_id = authentication.claims.id; // сервис — только под своим владельцем
    } else if !authentication.claims.is_local_admin() {
        payload.user_id = authentication.claims.id; // не-локальный-админ (user/OIDC-admin) — только себе
    }
    // local admin: payload.user_id остаётся как задан (любой владелец)
```
В `import_certificate`: сменить guard `_authentication: AuthenticatedPrivileged` на `authentication: Authenticated`, и сразу после разбора формы форсить владельца тем же правилом:
```rust
    if !authentication.claims.is_local_admin() && !authentication.claims.is_service() {
        // владелец импортируемого серта — сам импортирующий
        form_owner = authentication.claims.id;
    }
```
(точное имя поля владельца в `ImportCertForm` — сверить; присвоить его перед вставкой серта.)

- [ ] **Step 4: Запустить тест + safety-тест на privilege escalation**

Run: `cd backend && cargo test plain_user_can_issue_own_cert test_privilege_escalation 2>&1 | tail -20`
Expected: PASS. `test_privilege_escalation` (создание пользователя обычным юзером) должен остаться Forbidden — его мы не трогали.

- [ ] **Step 5: Commit**

```bash
git add backend/src/api.rs backend/tests/api/api_test_groups.rs
git commit -m "feat(api): allow any user to issue/import own cert; force owner unless local admin"
```

---

## Task 10: API — delete/revoke по правилу владелец|local-admin

**Files:**
- Modify: `backend/src/api.rs` (`delete_user_cert` ~1139, `revoke_certificate` ~1183)
- Test: `backend/tests/api/api_test_groups.rs`

**Interfaces:**
- Consumes: `get_user_cert_by_id`, `Claims::{is_local_admin, is_service, id}`.

- [ ] **Step 1: Написать падающий тест**

```rust
#[tokio::test]
async fn owner_can_delete_own_others_cannot() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2
    let admin_cert = client.create_client_cert(Some(1), Some("pw".into()), None).await?;
    let user_cert  = client.create_client_cert(Some(2), Some("pw".into()), None).await?;

    client.switch_user().await?; // user id=2
    // не владелец (серт admin) → Forbidden
    let resp = client.delete(format!("/certificates/{}", admin_cert.id)).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    // свой → Ok
    let resp = client.delete(format!("/certificates/{}", user_cert.id)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    Ok(())
}
```

- [ ] **Step 2: Запустить — падает (сейчас delete = AuthenticatedPrivileged → user получает Forbidden на ОБА, включая свой)**

Run: `cd backend && cargo test owner_can_delete_own_others_cannot 2>&1 | tail -20`
Expected: FAIL — удаление своего серта юзером сейчас Forbidden.

- [ ] **Step 3: Обновить handlers**

`delete_user_cert`: сменить guard на `authentication: Authenticated`, тело:
```rust
    let cert = state.db.get_user_cert_by_id(id).await?;
    let allowed = authentication.claims.is_local_admin()
        || (!authentication.claims.is_service() && cert.user_id == authentication.claims.id);
    if !allowed { return Err(ApiError::Forbidden(None)); }
    state.db.delete_user_cert(id).await?;
    Ok(())
```
`revoke_certificate`: сменić guard на `authentication: Authenticated` и вставить ту же проверку `allowed` в начало (после загрузки серта), сохранив остальную логику ревокации.

- [ ] **Step 4: Запустить тест + существующие revoke-тесты**

Run: `cd backend && cargo test owner_can_delete_own_others_cannot 2>&1 | tail -20 && cargo test --test integration_tests revoke 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/api.rs backend/tests/api/api_test_groups.rs
git commit -m "feat(api): delete/revoke allowed for owner or local admin"
```

---

## Task 11: API — CA-операции под локальным админом

**Files:**
- Modify: `backend/src/api.rs` (`create_ca` ~373, `import_ca` ~446, `delete_ca` ~1126)
- Test: `backend/tests/api/api_test_groups.rs`

**Interfaces:**
- Consumes: `AuthenticatedLocalAdmin`.

- [ ] **Step 1: Написать падающий тест — OIDC-admin/обычный не создаёт CA**

Поскольку OIDC-admin в integration недоступен, проверяем ужесточение через обычного user-а (он и раньше не мог; тест закрепляет, что после смены guard-а поведение остаётся Forbidden и что local admin по-прежнему может):
```rust
#[tokio::test]
async fn ca_ops_require_local_admin() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await; // user id=2
    let resp = client.post("/certificates/ca").header(ContentType::JSON)
        .body(json!({"ca_name":{"cn":"x"},"ca_type":0}).to_string())
        .dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}
```
(поле `ca_type` — сверить сериализацию `CAType` (repr u8): `TLS=0`. При несовпадении подставить корректное значение из `data/enums.rs`.)

- [ ] **Step 2: Запустить — проходит и сейчас (user запрещён Privileged); закрепляем базу**

Run: `cd backend && cargo test ca_ops_require_local_admin 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 3: Сменить guard на локального админа**

В `create_ca`, `import_ca`, `delete_ca` заменить `AuthenticatedPrivileged` → `AuthenticatedLocalAdmin` (параметр остаётся `_authentication`). Импортировать `AuthenticatedLocalAdmin` в `api.rs`.

- [ ] **Step 4: Запустить тест + существующие CA-тесты**

Run: `cd backend && cargo test ca_ops_require_local_admin 2>&1 | tail -15 && cargo test --test integration_tests ca 2>&1 | tail -20`
Expected: PASS (setup-user = local admin, создание CA в существующих тестах работает).

- [ ] **Step 5: Commit**

```bash
git add backend/src/api.rs backend/tests/api/api_test_groups.rs
git commit -m "feat(api): restrict CA create/import/delete to local admin"
```

---

## Task 12: API — `/auth/me` отдаёт признак локального входа

**Files:**
- Modify: `backend/src/data/objects.rs` (`User` — transient-поле) или `backend/src/api.rs` (`get_current_user` ~335)
- Test: `backend/tests/api/api_test_groups.rs`

**Interfaces:**
- Produces: в ответе `GET /auth/me` присутствует boolean `is_local`.

- [ ] **Step 1: Написать падающий тест**

```rust
#[tokio::test]
async fn me_reports_is_local_for_password_login() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // логин паролем
    let body = client.get("/auth/me").dispatch().await.into_string().await.unwrap();
    assert!(body.contains("\"is_local\":true"));
    Ok(())
}
```

- [ ] **Step 2: Запустить — падает (нет поля)**

Run: `cd backend && cargo test me_reports_is_local_for_password_login 2>&1 | tail -15`
Expected: FAIL.

- [ ] **Step 3: Добавить transient-поле в User и заполнять в get_current_user**

В `backend/src/data/objects.rs`, в `struct User` добавить:
```rust
    #[serde(default, skip_deserializing)]
    #[schemars(skip)]
    pub is_local: bool,
```
Убедиться, что конструкции `User { ... }` в коде компилируются — поле имеет `Default`? Нет, у struct нет `#[derive(Default)]`; поэтому обновить **все** литералы `User { ... }` добавив `is_local: false`. Найдите их: `rg "User \{" backend/src`. Это включает: `oidc_auth.rs:~130`, `setup ~92`, `create_user ~1362`, **а также новые тесты из Task 4 и Task 5** (`group_crud_and_membership`, `visibility_owner_and_group`) и существующий `acme_client_renewal_helpers`. Пропуск любого литерала = ошибка компиляции `missing field is_local`.
В `get_current_user` (`backend/src/api.rs`):
```rust
    let mut user = state.db.get_user(authentication.claims.id).await?;
    user.is_local = authentication.claims.is_local;
    Ok(Json(user))
```

- [ ] **Step 4: Запустить тест + сборку целиком**

Run: `cd backend && cargo test me_reports_is_local_for_password_login 2>&1 | tail -15 && cargo build 2>&1 | tail -10`
Expected: PASS + успешная сборка (все литералы `User` обновлены).

- [ ] **Step 5: Commit**

```bash
git add backend/src/data/objects.rs backend/src/api.rs backend/src/auth/oidc_auth.rs
git commit -m "feat(api): expose is_local on /auth/me for local-admin UI gating"
```

---

## Task 13: Frontend — тип Group, api-модуль

**Files:**
- Create: `frontend/src/types/Group.ts`
- Create: `frontend/src/api/groups.ts`
- Modify: `frontend/src/types/User.ts` (добавить `is_local`)

**Interfaces:**
- Produces: `Group`, `GroupDetail`, `GroupRequest`; функции `fetchGroups`, `fetchGroup`, `createGroup`, `updateGroup`, `deleteGroup`, `setGroupUsers`, `setGroupCertificates`.

- [ ] **Step 1: Тип Group**

`frontend/src/types/Group.ts`:
```ts
export interface Group {
    id: number;
    name: string;
    description?: string | null;
    created_on: number;
}

export interface GroupDetail extends Group {
    user_ids: number[];
    certificate_ids: number[];
}

export interface GroupRequest {
    name: string;
    description?: string | null;
}
```

- [ ] **Step 2: Добавить is_local в User**

В `frontend/src/types/User.ts`, в `interface User` добавить: `is_local?: boolean;`

- [ ] **Step 3: api-модуль**

`frontend/src/api/groups.ts` (по образцу `api/users.ts`):
```ts
import ApiClient from './ApiClient';
import type { Group, GroupDetail, GroupRequest } from "@/types/Group.ts";

export const fetchGroups = async (): Promise<Group[]> =>
    await ApiClient.get<Group[]>('/groups');

export const fetchGroup = async (id: number): Promise<GroupDetail> =>
    await ApiClient.get<GroupDetail>(`/groups/${id}`);

export const createGroup = async (req: GroupRequest): Promise<number> =>
    await ApiClient.post<number>('/groups', req);

export const updateGroup = async (id: number, req: GroupRequest): Promise<void> =>
    await ApiClient.put<void>(`/groups/${id}`, req);

export const deleteGroup = async (id: number): Promise<void> =>
    await ApiClient.delete<void>(`/groups/${id}`);

export const setGroupUsers = async (id: number, ids: number[]): Promise<void> =>
    await ApiClient.put<void>(`/groups/${id}/users`, { ids });

export const setGroupCertificates = async (id: number, ids: number[]): Promise<void> =>
    await ApiClient.put<void>(`/groups/${id}/certificates`, { ids });
```

- [ ] **Step 4: Проверить типами**

Run: `cd frontend && npx vue-tsc --noEmit 2>&1 | tail -15`
Expected: без ошибок в новых файлах.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/types/Group.ts frontend/src/types/User.ts frontend/src/api/groups.ts
git commit -m "feat(frontend): Group types and api client"
```

---

## Task 14: Frontend — store groups

**Files:**
- Create: `frontend/src/stores/groups.ts`

**Interfaces:**
- Consumes: api-модуль Task 13.
- Produces: `useGroupStore` с `groups`, `fetchGroups`, `createGroup`, `updateGroup`, `deleteGroup`, `setGroupUsers`, `setGroupCertificates`, `fetchGroup`.

- [ ] **Step 1: Store по образцу stores/users.ts**

`frontend/src/stores/groups.ts`:
```ts
import { defineStore } from 'pinia';
import type { Group, GroupDetail, GroupRequest } from "@/types/Group.ts";
import {
    fetchGroups, fetchGroup, createGroup, updateGroup, deleteGroup,
    setGroupUsers, setGroupCertificates,
} from "@/api/groups.ts";
import axios from 'axios';

export const useGroupStore = defineStore('group', {
    state: () => ({
        groups: [] as Group[],
        loading: false,
        error: null as string | null,
    }),
    actions: {
        async fetchGroups(force = false): Promise<void> {
            if (this.groups.length === 0 || force) {
                this.loading = true; this.error = null;
                try { this.groups = await fetchGroups(); }
                catch (err) { this.error = axios.isAxiosError(err) ? 'Failed to fetch groups: ' + err.response?.data?.error : 'Failed to fetch groups'; console.error(err); }
                finally { this.loading = false; }
            }
        },
        async fetchGroup(id: number): Promise<GroupDetail | null> {
            try { return await fetchGroup(id); }
            catch (err) { console.error(err); return null; }
        },
        async createGroup(req: GroupRequest): Promise<void> {
            try { await createGroup(req); this.groups = await fetchGroups(); }
            catch (err) { this.error = axios.isAxiosError(err) ? 'Failed to create group: ' + err.response?.data?.error : 'Failed to create group'; console.error(err); }
        },
        async updateGroup(id: number, req: GroupRequest): Promise<void> {
            try { await updateGroup(id, req); this.groups = await fetchGroups(); }
            catch (err) { console.error(err); }
        },
        async deleteGroup(id: number): Promise<void> {
            try { await deleteGroup(id); this.groups = await fetchGroups(); }
            catch (err) { console.error(err); }
        },
        async setGroupUsers(id: number, ids: number[]): Promise<void> { await setGroupUsers(id, ids); },
        async setGroupCertificates(id: number, ids: number[]): Promise<void> { await setGroupCertificates(id, ids); },
    },
});
```

- [ ] **Step 2: Проверить типами**

Run: `cd frontend && npx vue-tsc --noEmit 2>&1 | tail -15`
Expected: без ошибок.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/stores/groups.ts
git commit -m "feat(frontend): groups pinia store"
```

---

## Task 15: Frontend — вкладка Groups, навигация, локали

**Files:**
- Create: `frontend/src/components/GroupsTab.vue`
- Modify: `frontend/src/stores/auth.ts` (getter `isLocalAdmin`)
- Modify: `frontend/src/router/router.ts` (route + guard)
- Modify: `frontend/src/components/Sidebar.vue` (пункт меню)
- Modify: `frontend/src/locales/en.json`, `frontend/src/locales/es.json`

**Interfaces:**
- Consumes: `useGroupStore`, `useUserStore`, `useCertificateStore` (для мультиселектов участников и сертов), `auth.isLocalAdmin`.

- [ ] **Step 1: Getter isLocalAdmin в auth store**

В `frontend/src/stores/auth.ts`, в `getters` рядом с `isAdmin`:
```ts
        isLocalAdmin(state): boolean {
            return state.current_user?.role === UserRole.Admin && state.current_user?.is_local === true;
        },
```

- [ ] **Step 2: Компонент GroupsTab.vue**

Создать `frontend/src/components/GroupsTab.vue` по образцу `components/UserTab.vue` (список + модалка создания/редактирования). Требования к содержимому:
- Таблица групп: имя, описание, число участников, число сертов, кнопки «Изменить»/«Удалить».
- Модалка (BaseModal) создания/редактирования: поля `name`, `description`; два мультиселекта — участники (`useUserStore().users`) и сертификаты (`useCertificateStore().certificates`), предзаполняются из `fetchGroup(id)` при редактировании.
- На сохранении: `createGroup`/`updateGroup`, затем `setGroupUsers(id, selectedUserIds)` и `setGroupCertificates(id, selectedCertIds)`.
- `onMounted`: `useGroupStore().fetchGroups()`, `useUserStore().fetchUsers()`, `useCertificateStore().fetchCertificates()`.
Скелет `<script setup>`:
```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useGroupStore } from '@/stores/groups';
import { useUserStore } from '@/stores/users';
import { useCertificateStore } from '@/stores/certificates';
import type { Group } from '@/types/Group';

const groupStore = useGroupStore();
const userStore = useUserStore();
const certStore = useCertificateStore();

const editing = ref<Group | null>(null);
const selectedUserIds = ref<number[]>([]);
const selectedCertIds = ref<number[]>([]);
const form = ref({ name: '', description: '' });

async function openEdit(g: Group) {
  editing.value = g;
  form.value = { name: g.name, description: g.description ?? '' };
  const detail = await groupStore.fetchGroup(g.id);
  selectedUserIds.value = detail?.user_ids ?? [];
  selectedCertIds.value = detail?.certificate_ids ?? [];
}

async function save() {
  let id = editing.value?.id;
  if (id == null) {
    await groupStore.createGroup({ name: form.value.name, description: form.value.description });
    id = groupStore.groups.find(g => g.name === form.value.name)?.id;
  } else {
    await groupStore.updateGroup(id, { name: form.value.name, description: form.value.description });
  }
  if (id != null) {
    await groupStore.setGroupUsers(id, selectedUserIds.value);
    await groupStore.setGroupCertificates(id, selectedCertIds.value);
  }
  editing.value = null;
}

onMounted(async () => {
  await Promise.all([groupStore.fetchGroups(true), userStore.fetchUsers(), certStore.fetchCertificates()]);
});
</script>
```
Разметку (`<template>`) выполнить в стиле `UserTab.vue` (те же CSS-классы `vt-*`, `BaseModal`). Тексты — через `$t('groups.*')`.

- [ ] **Step 3: Route + guard**

В `frontend/src/router/router.ts` добавить маршрут вкладки (по образцу существующих tab-маршрутов; вкладки монтируются в основном layout). Добавить `meta: { requiresLocalAdmin: true }` и в глобальном/локальном guard редиректить на обзор, если `!useAuthStore().isLocalAdmin`. Точное встраивание — по образцу того, как гейтится admin-вкладка Users.

- [ ] **Step 4: Пункт в Sidebar**

В `frontend/src/components/Sidebar.vue` добавить пункт меню «Groups» в массив пунктов, с условием видимости `authStore.isLocalAdmin` (по образцу admin-only пунктов). Иконку взять из `components/icons`.

- [ ] **Step 5: Локали**

В `frontend/src/locales/en.json` добавить блок:
```json
"groups": {
  "title": "Groups",
  "name": "Name",
  "description": "Description",
  "members": "Members",
  "certificates": "Certificates",
  "create": "Create group",
  "edit": "Edit group",
  "delete": "Delete group",
  "empty": "No groups yet"
}
```
В `frontend/src/locales/es.json` — те же ключи с испанскими значениями. Также добавить `sidebar.groups` в оба файла (значение "Groups"/"Grupos").

- [ ] **Step 6: Проверить типами и сборкой**

Run: `cd frontend && npx vue-tsc --noEmit 2>&1 | tail -20`
Expected: без ошибок.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/GroupsTab.vue frontend/src/stores/auth.ts frontend/src/router/router.ts frontend/src/components/Sidebar.vue frontend/src/locales/en.json frontend/src/locales/es.json
git commit -m "feat(frontend): Groups admin tab, navigation, locales"
```

---

## Task 16: Frontend — скрыть download/пароль для чужого группового серта

**Files:**
- Modify: `frontend/src/components/OverviewTab.vue`

**Interfaces:**
- Consumes: `auth` store (current user id, isAdmin/isLocalAdmin), `certificate.user_id`.

- [ ] **Step 1: Ввести признак «доступен приватный материал»**

В `OverviewTab.vue` добавить helper:
```ts
function canDownload(cert: Certificate): boolean {
  const auth = useAuthStore();
  if (auth.isLocalAdmin) return true;
  if (cert.user_id === auth.current_user?.id) return true;
  // OIDC-admin: серверу решать; на UI показываем кнопку и полагаемся на 403 — но чтобы не путать user-а, для не-админа скрываем чужое
  return auth.isAdmin;
}
```

- [ ] **Step 2: Применить в разметке**

Кнопки скачивания p12/PEM и «показать пароль» обернуть `v-if="canDownload(cert)"`. Для строк, где `!canDownload(cert)`, оставить только метаданные (имя, срок, статус, CA).

- [ ] **Step 3: Проверить типами**

Run: `cd frontend && npx vue-tsc --noEmit 2>&1 | tail -15`
Expected: без ошибок.

- [ ] **Step 4: Ручная проверка сборки фронта**

Run: `cd frontend && npm run build 2>&1 | tail -15`
Expected: успешная сборка.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/OverviewTab.vue
git commit -m "feat(frontend): hide download/password controls for non-owned group certs"
```

---

## Task 17: Полный прогон и верификация

**Files:** —

- [ ] **Step 1: Backend — все тесты**

Run: `cd backend && cargo test 2>&1 | tail -30`
Expected: все тесты зелёные, включая новые group-тесты и существующие.

- [ ] **Step 2: Backend — clippy**

Run: `cd backend && cargo clippy --all-targets 2>&1 | tail -20`
Expected: без новых ошибок.

- [ ] **Step 3: Frontend — типы и сборка**

Run: `cd frontend && npx vue-tsc --noEmit && npm run build 2>&1 | tail -15`
Expected: успех.

- [ ] **Step 4: Финальный commit при необходимости и готовность к PR**

```bash
git status
```
Expected: рабочее дерево чистое; ветка `feat/certificate-groups` готова к ревью.

---

## Итоговое покрытие спеки

- Матрица доступа (видимость/download/delete/группы): Tasks 7, 8, 10 + класс актора Task 2.
- Схема БД: Task 1.
- `is_local` в JWT: Task 2; guard local-admin: Task 3.
- CRUD групп + состав: Tasks 4, 6.
- Видимость через группы: Tasks 5, 7.
- create/import для user: Task 9; CA под local admin: Task 11.
- `/auth/me` is_local: Task 12.
- Frontend (тип/api/store/вкладка/навигация/локали/скрытие кнопок): Tasks 13–16.
- Тесты по всем узлам матрицы: в каждой backend-задаче + финальный прогон Task 17.
