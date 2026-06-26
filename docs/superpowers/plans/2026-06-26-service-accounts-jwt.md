# Service accounts + Bearer/JWT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let automated clients authenticate via service-account credentials exchanged for a short-lived Bearer JWT and pull/issue certificates, with granular scopes and a per-user management UI.

**Architecture:** A new `service_accounts` table (owner-bound). `POST /auth/token` exchanges `client_id`+`secret` for a stateless service JWT (`id = owner user_id`, `role = User`, `scopes`). `authenticate_auth_token` accepts the token from the cookie OR an `Authorization: Bearer` header; service tokens skip the in-memory JTI check. Issue/read endpoints gate on scopes for service tokens while preserving the human cookie flow. A Vue modal in the Users section manages accounts.

**Tech Stack:** Rust, Rocket 0.5.1, rusqlite/SQLCipher, jsonwebtoken (HS256), argon2; Vue 3 + TS + Pinia + PrimeVue 4 + vue-i18n.

## Global Constraints

- `serial`/hex and timestamp conventions: timestamps are epoch **milliseconds** (`chrono::Utc::now().timestamp_millis()`).
- Service JWT MUST carry `id = owner user_id`, `role = UserRole::User`, and a `service` claim block; it MUST NOT be inserted into `JTI_STORE` (stateless, survives restart).
- Human token behavior (cookie, JTI-stateful logout) MUST remain unchanged.
- Allowed scopes this iteration: exactly `cert:read` and `cert:issue`. Validate against this set; reject unknown scopes with `400`.
- The one-time `secret` is returned ONLY in the create response; only its argon2 hash is stored. `client_id` is public.
- `POST /auth/token` returns a uniform `401` for unknown/revoked/bad-secret (no oracle).
- A service token issuing a cert MUST bind the cert to its owner (`payload.user_id = claims.id`), never another user.
- Management endpoints are Admin-only (`AuthenticatedPrivileged`).
- Scopes are stored as a CSV string in SQLite and represented as `Vec<String>` in Rust.
- Reuse the existing `ARGON2` static (`crate::constants::ARGON2`) for secret hashing.
- Run backend tests with `cargo test` from `backend/` (parallel/default). Pre-existing `test_ssh_revocation_and_krl` fails on base — ignore it. Build the frontend with `npm run build` from `frontend/`.

---

### Task 1: Service-account model, migration, secret hashing, DB CRUD

**Files:**
- Create: `backend/migrations/12-serviceaccounts/up.sql`, `backend/migrations/12-serviceaccounts/down.sql`
- Create: `backend/src/auth/service_auth.rs`
- Modify: `backend/src/auth/mod.rs` (add `pub(crate) mod service_auth;`)
- Modify: `backend/src/data/objects.rs` (add `ServiceAccount` struct)
- Modify: `backend/src/db.rs` (add CRUD methods)

**Interfaces:**
- Produces:
  - `ServiceAccount { id: i64, name: String, client_id: String, secret_hash: String (serde-skip), user_id: i64, scopes: Vec<String>, created_at: i64, last_used_at: Option<i64>, revoked: bool }`
  - `service_auth::hash_secret(secret: &str) -> Result<String, ApiError>`, `service_auth::verify_secret(secret: &str, hash: &str) -> bool`, `service_auth::generate_credentials() -> (String /*client_id*/, String /*secret*/)`
  - DB: `insert_service_account(sa: ServiceAccount) -> Result<ServiceAccount>`, `get_service_account_by_client_id(client_id: String) -> Result<Option<ServiceAccount>>`, `list_service_accounts_by_user(user_id: i64) -> Result<Vec<ServiceAccount>>`, `revoke_service_account(id: i64) -> Result<()>`, `touch_service_account_last_used(id: i64) -> Result<()>`

- [ ] **Step 1: Write the migration**

`backend/migrations/12-serviceaccounts/up.sql`:

```sql
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
```

`backend/migrations/12-serviceaccounts/down.sql`:

```sql
DROP INDEX idx_service_accounts_client_id;
DROP TABLE service_accounts;
```

- [ ] **Step 2: Add the `ServiceAccount` struct**

In `backend/src/data/objects.rs`, add (match the file's existing `use` for Serialize/Deserialize/JsonSchema):

```rust
#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct ServiceAccount {
    pub id: i64,
    pub name: String,
    pub client_id: String,
    #[serde(skip)]
    pub secret_hash: String,
    pub user_id: i64,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked: bool,
}
```

- [ ] **Step 3: Create `service_auth.rs` with hashing + credential generation, and a unit test**

`backend/src/auth/service_auth.rs`:

```rust
use crate::constants::ARGON2;
use crate::ApiError;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{PasswordHasher, PasswordVerifier};
use uuid::Uuid;

/// Argon2-hash a service-account secret for storage.
pub(crate) fn hash_secret(secret: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(ARGON2
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|_| ApiError::Other("Failed to hash secret".to_string()))?
        .serialize()
        .to_string())
}

/// Verify a presented secret against a stored hash.
pub(crate) fn verify_secret(secret: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => ARGON2.verify_password(secret.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Generate a public client_id and a high-entropy secret (256 bits via two UUIDv4).
pub(crate) fn generate_credentials() -> (String, String) {
    let client_id = format!("svc_{}", Uuid::new_v4().simple());
    let secret = format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    (client_id, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrips() {
        let (_cid, secret) = generate_credentials();
        let hash = hash_secret(&secret).unwrap();
        assert!(verify_secret(&secret, &hash));
        assert!(!verify_secret("wrong-secret", &hash));
    }

    #[test]
    fn credentials_have_expected_shape() {
        let (cid, secret) = generate_credentials();
        assert!(cid.starts_with("svc_"));
        assert_eq!(secret.len(), 64); // two 32-char simple UUIDs
    }
}
```

In `backend/src/auth/mod.rs` add:

```rust
pub(crate) mod service_auth;
```

- [ ] **Step 4: Run the unit test (fails to compile until module is wired)**

Run: `cd backend && cargo test --features test-mode --lib service_auth 2>&1 | tail -20`
Expected: PASS (2 tests). If `ApiError`/`constants::ARGON2` import paths differ, adjust to the crate's actual paths shown in `password_auth.rs` (which imports `crate::constants::ARGON2` and `crate::ApiError`).

- [ ] **Step 5: Add DB CRUD methods**

In `backend/src/db.rs`, inside an `impl VaulTLSDB` block, add. Scopes are joined/split on `,`:

```rust
pub(crate) async fn insert_service_account(&self, mut sa: ServiceAccount) -> Result<ServiceAccount> {
    db_do!(self.pool, |conn: &Connection| {
        let scopes_csv = sa.scopes.join(",");
        conn.execute(
            "INSERT INTO service_accounts (name, client_id, secret_hash, user_id, scopes, created_at, last_used_at, revoked) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0)",
            params![sa.name, sa.client_id, sa.secret_hash, sa.user_id, scopes_csv, sa.created_at],
        )?;
        sa.id = conn.last_insert_rowid();
        Ok(sa)
    })
}

pub(crate) async fn get_service_account_by_client_id(&self, client_id: String) -> Result<Option<ServiceAccount>> {
    db_do!(self.pool, |conn: &Connection| {
        let result = conn.query_row(
            "SELECT id, name, client_id, secret_hash, user_id, scopes, created_at, last_used_at, revoked \
             FROM service_accounts WHERE client_id = ?1",
            params![client_id],
            service_account_from_row,
        );
        match result {
            Ok(sa) => Ok(Some(sa)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    })
}

pub(crate) async fn list_service_accounts_by_user(&self, user_id: i64) -> Result<Vec<ServiceAccount>> {
    db_do!(self.pool, |conn: &Connection| {
        let mut stmt = conn.prepare(
            "SELECT id, name, client_id, secret_hash, user_id, scopes, created_at, last_used_at, revoked \
             FROM service_accounts WHERE user_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![user_id], service_account_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<ServiceAccount>>>()?)
    })
}

pub(crate) async fn revoke_service_account(&self, id: i64) -> Result<()> {
    db_do!(self.pool, |conn: &Connection| {
        conn.execute("UPDATE service_accounts SET revoked = 1 WHERE id = ?1", params![id])?;
        Ok(())
    })
}

pub(crate) async fn touch_service_account_last_used(&self, id: i64, now_ms: i64) -> Result<()> {
    db_do!(self.pool, |conn: &Connection| {
        conn.execute("UPDATE service_accounts SET last_used_at = ?1 WHERE id = ?2", params![now_ms, id])?;
        Ok(())
    })
}
```

Add this free function near the other row-mapping helpers in `db.rs`:

```rust
fn service_account_from_row(row: &rusqlite::Row) -> rusqlite::Result<ServiceAccount> {
    let scopes_csv: String = row.get(5)?;
    let scopes = if scopes_csv.is_empty() {
        Vec::new()
    } else {
        scopes_csv.split(',').map(|s| s.to_string()).collect()
    };
    Ok(ServiceAccount {
        id: row.get(0)?,
        name: row.get(1)?,
        client_id: row.get(2)?,
        secret_hash: row.get(3)?,
        user_id: row.get(4)?,
        scopes,
        created_at: row.get(6)?,
        last_used_at: row.get(7)?,
        revoked: row.get::<_, i64>(8)? != 0,
    })
}
```

Ensure `ServiceAccount` is imported in `db.rs` (the file already imports from `crate::data::objects`; add `ServiceAccount` to that import).

- [ ] **Step 6: Verify it builds**

Run: `cd backend && cargo build 2>&1 | tail -20`
Expected: builds (unused-method warnings are fine — consumed in later tasks).

- [ ] **Step 7: Commit**

```bash
cd backend && git add migrations/12-serviceaccounts src/auth/service_auth.rs src/auth/mod.rs src/data/objects.rs src/db.rs
git commit -m "feat(auth): service_accounts table, model, secret hashing, DB CRUD"
```

---

### Task 2: Claims extension, service token, Bearer acceptance, scope helpers

**Files:**
- Modify: `backend/src/auth/session_auth.rs`

**Interfaces:**
- Consumes: `generate_token` (existing), `authenticate_auth_token` (existing), `Claims`.
- Produces:
  - `Claims` gains `service: Option<ServiceClaims>` where `ServiceClaims { account_id: i64, scopes: Vec<String> }`.
  - `generate_service_token(jwt_key: &[u8], owner_user_id: i64, account_id: i64, scopes: Vec<String>) -> Result<String, ApiError>`
  - `Claims::is_service(&self) -> bool`, `Claims::has_scope(&self, scope: &str) -> bool`
  - `authenticate_auth_token` now also reads `Authorization: Bearer` and skips the JTI check for service tokens.

- [ ] **Step 1: Extend `Claims` and add `ServiceClaims`**

In `backend/src/auth/session_auth.rs`, replace the `Claims` struct with:

```rust
/// Service-token-only claim block (absent for human tokens).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct ServiceClaims {
    pub(crate) account_id: i64,
    pub(crate) scopes: Vec<String>,
}

/// JWT claims
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct Claims {
    pub(crate) jti: String,
    pub(crate) id: i64,
    pub(crate) role: UserRole,
    pub(crate) exp: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) service: Option<ServiceClaims>,
}

impl Claims {
    pub(crate) fn is_service(&self) -> bool {
        self.service.is_some()
    }
    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        self.service
            .as_ref()
            .is_some_and(|s| s.scopes.iter().any(|x| x == scope))
    }
}
```

- [ ] **Step 2: Set `service: None` in the existing `generate_token`**

In `generate_token`, the `Claims { ... }` literal must now include `service: None`:

```rust
    let claims = Claims {
        jti: jti.clone(),
        exp: expires_unix,
        id: user_id,
        role: user_role,
        service: None,
    };
```

- [ ] **Step 3: Add `generate_service_token`**

After `generate_token` add:

```rust
/// Build a stateless service JWT: id = owner user, role = User, carries scopes.
/// NOT registered in JTI_STORE (survives restarts; revoked via DB flag + short exp).
pub(crate) fn generate_service_token(
    jwt_key: &[u8],
    owner_user_id: i64,
    account_id: i64,
    scopes: Vec<String>,
) -> Result<String, ApiError> {
    let expires = SystemTime::now() + Duration::from_secs(60 * 60 /* 1 hour */);
    let expires_unix = expires.duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let claims = Claims {
        jti: Uuid::new_v4().to_string(),
        exp: expires_unix,
        id: owner_user_id,
        role: UserRole::User,
        service: Some(ServiceClaims { account_id, scopes }),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_key),
    )
    .map_err(|_| ApiError::Other("Failed to generate service JWT".to_string()))
}
```

- [ ] **Step 4: Accept Bearer and skip JTI for service tokens**

Replace the body of `authenticate_auth_token` with:

```rust
pub(crate) fn authenticate_auth_token(request: &Request<'_>) -> Option<Claims> {
    // Prefer the private cookie (human sessions); fall back to Authorization: Bearer (services).
    let token = match request.cookies().get_private("auth_token") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            let header = request.headers().get_one("Authorization")?;
            header.strip_prefix("Bearer ")?.trim().to_string()
        }
    };

    let config = request.rocket().state::<AppState>()?;
    let jwt_key = config.settings.get_jwt_key().ok()?;
    let decoding_key = DecodingKey::from_secret(&jwt_key);
    let validation = Validation::default();

    let claims = decode::<Claims>(&token, &decoding_key, &validation).ok()?.claims;

    // Service tokens are stateless — no JTI membership requirement.
    if claims.service.is_some() {
        return Some(claims);
    }

    match JTI_STORE.read().contains(&claims.jti) {
        true => Some(claims),
        false => None,
    }
}
```

- [ ] **Step 5: Write a unit test for service-token shape**

At the end of `session_auth.rs` add (the file already has access to `UserRole`):

```rust
#[cfg(test)]
mod service_token_tests {
    use super::*;

    #[test]
    fn service_token_carries_scopes_and_user_role() {
        let key = b"0123456789abcdef0123456789abcdef";
        let token = generate_service_token(key, 7, 3, vec!["cert:read".into()]).unwrap();
        let claims = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(key),
            &Validation::default(),
        )
        .unwrap()
        .claims;
        assert_eq!(claims.id, 7);
        assert_eq!(claims.role, UserRole::User);
        assert!(claims.is_service());
        assert!(claims.has_scope("cert:read"));
        assert!(!claims.has_scope("cert:issue"));
    }
}
```

- [ ] **Step 6: Run the unit test**

Run: `cd backend && cargo test --features test-mode --lib service_token 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 7: Full build (existing human-token code must still compile)**

Run: `cd backend && cargo build 2>&1 | tail -20`
Expected: builds. (Any other `Claims { ... }` literal in the codebase — e.g. OIDC login — must also gain `service: None`; grep `Claims {` and fix each. The compiler will flag missing fields.)

- [ ] **Step 8: Commit**

```bash
cd backend && git add src/auth/session_auth.rs src/api.rs 2>/dev/null; git add -A backend/src
git commit -m "feat(auth): service claims, generate_service_token, Bearer acceptance, scope helpers"
```

---

### Task 3: Token exchange endpoint `POST /auth/token`

**Files:**
- Modify: `backend/src/data/api.rs` (request/response types)
- Modify: `backend/src/api.rs` (handler)
- Modify: `backend/src/lib.rs` (mount)
- Test: `backend/tests/api/api_test_service_accounts.rs` (new), `backend/tests/api/mod.rs`

**Interfaces:**
- Consumes: `get_service_account_by_client_id`, `verify_secret`, `generate_service_token`, `touch_service_account_last_used`, `settings.get_jwt_key()`.
- Produces: `POST /api/auth/token` → `Json<ServiceTokenResponse>`.

- [ ] **Step 1: Add request/response types**

In `backend/src/data/api.rs`:

```rust
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ServiceTokenRequest {
    pub client_id: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ServiceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scopes: Vec<String>,
}
```

- [ ] **Step 2: Write the failing integration test**

Create `backend/tests/api/api_test_service_accounts.rs`. This file hosts Task 3/4/5 tests. It defines a helper to create a service account once Task 4's endpoint exists — but for THIS task we test the exchange against a directly-inserted account is not possible from the client, so the exchange test is written here and will pass only after Task 4 provides creation. To keep Task 3 independently testable, test the failure path now (unknown client_id → 401), which needs only this endpoint:

```rust
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};

#[tokio::test]
async fn token_exchange_unknown_client_is_401() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let body = r#"{"client_id":"svc_does_not_exist","secret":"nope"}"#;
    let resp = client
        .post("/auth/token")
        .header(ContentType::JSON)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
    Ok(())
}
```

Register it in `backend/tests/api/mod.rs`:

```rust
mod api_test_service_accounts;
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd backend && cargo test --test integration_tests token_exchange_unknown_client_is_401 2>&1 | tail -20`
Expected: FAIL (route not found → 404).

- [ ] **Step 4: Implement the handler**

In `backend/src/api.rs` add (imports: `use crate::data::api::{ServiceTokenRequest, ServiceTokenResponse};`, `use crate::auth::service_auth::verify_secret;`, `use crate::auth::session_auth::generate_service_token;` — match existing import style):

```rust
#[openapi(tag = "Authentication")]
#[post("/auth/token", format = "json", data = "<payload>")]
/// Exchange service-account client_id + secret for a short-lived Bearer JWT.
pub(crate) async fn service_token(
    state: &State<AppState>,
    payload: Json<ServiceTokenRequest>,
) -> Result<Json<ServiceTokenResponse>, ApiError> {
    let unauthorized = || ApiError::Unauthorized(Some("Invalid client credentials".to_string()));

    let sa = state
        .db
        .get_service_account_by_client_id(payload.client_id.clone())
        .await
        .map_err(|_| unauthorized())?
        .ok_or_else(unauthorized)?;

    if sa.revoked || !verify_secret(&payload.secret, &sa.secret_hash) {
        return Err(unauthorized());
    }

    let jwt_key = state.settings.get_jwt_key()?;
    let token = generate_service_token(&jwt_key, sa.user_id, sa.id, sa.scopes.clone())?;

    let now = chrono::Utc::now().timestamp_millis();
    let _ = state.db.touch_service_account_last_used(sa.id, now).await;

    Ok(Json(ServiceTokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        scopes: sa.scopes,
    }))
}
```

- [ ] **Step 5: Mount the route**

In `backend/src/lib.rs`, add `service_token,` to EVERY `openapi_get_routes![ ... ]` list (there are multiple — production `create_rocket` and the test rocket; grep for `login,` and add `service_token,` next to it in each).

- [ ] **Step 6: Run the test**

Run: `cd backend && cargo test --test integration_tests token_exchange_unknown_client_is_401 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 7: Full suite**

Run: `cd backend && cargo test 2>&1 | tail -8`
Expected: green except the known pre-existing `test_ssh_revocation_and_krl`.

- [ ] **Step 8: Commit**

```bash
cd backend && git add src/data/api.rs src/api.rs src/lib.rs tests/api/api_test_service_accounts.rs tests/api/mod.rs
git commit -m "feat(auth): POST /auth/token service-token exchange endpoint"
```

---

### Task 4: Management endpoints (Admin) + full exchange round-trip test

**Files:**
- Modify: `backend/src/data/api.rs` (create request/response)
- Modify: `backend/src/api.rs` (3 handlers)
- Modify: `backend/src/lib.rs` (mount)
- Test: `backend/tests/api/api_test_service_accounts.rs`

**Interfaces:**
- Consumes: `insert_service_account`, `list_service_accounts_by_user`, `revoke_service_account`, `get_user`, `service_auth::{hash_secret, generate_credentials}`, `AuthenticatedPrivileged`.
- Produces: `POST /api/users/<id>/service-accounts`, `GET /api/users/<id>/service-accounts`, `DELETE /api/service-accounts/<sid>`.

- [ ] **Step 1: Add request/response types**

In `backend/src/data/api.rs`:

```rust
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateServiceAccountRequest {
    pub name: String,
    pub scopes: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ServiceAccountCreated {
    pub id: i64,
    pub name: String,
    pub client_id: String,
    pub secret: String,
    pub scopes: Vec<String>,
}
```

- [ ] **Step 2: Write the failing tests**

Append to `backend/tests/api/api_test_service_accounts.rs`. A helper logs in as admin, creates a service account, and exchanges it:

```rust
use serde_json::Value;

async fn create_service_account(client: &VaulTLSClient, user_id: i64, name: &str, scopes: &[&str]) -> Value {
    let scopes_json = serde_json::to_string(scopes).unwrap();
    let body = format!(r#"{{"name":"{name}","scopes":{scopes_json}}}"#);
    let resp = client
        .post(format!("/users/{user_id}/service-accounts"))
        .header(ContentType::JSON)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    serde_json::from_str(&resp.into_string().await.unwrap()).unwrap()
}

#[tokio::test]
async fn create_lists_and_revokes_service_account() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // admin, user id 1

    let created = create_service_account(&client, 1, "ci-bot", &["cert:read"]).await;
    assert!(created["secret"].as_str().unwrap().len() == 64);
    assert!(created["client_id"].as_str().unwrap().starts_with("svc_"));
    let client_id = created["client_id"].as_str().unwrap().to_string();
    let secret = created["secret"].as_str().unwrap().to_string();
    let sid = created["id"].as_i64().unwrap();

    // List returns it without a secret
    let resp = client.get("/users/1/service-accounts").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let list_body = resp.into_string().await.unwrap();
    assert!(list_body.contains("ci-bot"));
    assert!(!list_body.contains(&secret), "secret must never be listed");

    // Exchange works
    let token_resp = client
        .post("/auth/token")
        .header(ContentType::JSON)
        .body(format!(r#"{{"client_id":"{client_id}","secret":"{secret}"}}"#))
        .dispatch()
        .await;
    assert_eq!(token_resp.status(), Status::Ok);
    let tv: Value = serde_json::from_str(&token_resp.into_string().await.unwrap())?;
    assert_eq!(tv["token_type"], "Bearer");
    assert!(tv["access_token"].as_str().unwrap().len() > 20);

    // Revoke → exchange now fails
    let del = client.delete(format!("/service-accounts/{sid}")).dispatch().await;
    assert_eq!(del.status(), Status::Ok);
    let after = client
        .post("/auth/token")
        .header(ContentType::JSON)
        .body(format!(r#"{{"client_id":"{client_id}","secret":"{secret}"}}"#))
        .dispatch()
        .await;
    assert_eq!(after.status(), Status::Unauthorized);

    Ok(())
}

#[tokio::test]
async fn create_rejects_unknown_scope() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let resp = client
        .post("/users/1/service-accounts")
        .header(ContentType::JSON)
        .body(r#"{"name":"bad","scopes":["cert:delete"]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);
    Ok(())
}

#[tokio::test]
async fn management_requires_admin() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await;
    let resp = client.get("/users/1/service-accounts").dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cd backend && cargo test --test integration_tests service_account 2>&1 | tail -20`
Expected: FAIL (routes missing).

- [ ] **Step 4: Implement the three handlers**

In `backend/src/api.rs` add (imports: `use crate::data::api::{CreateServiceAccountRequest, ServiceAccountCreated};`, `use crate::data::objects::ServiceAccount;`, `use crate::auth::service_auth::{hash_secret, generate_credentials};`):

```rust
const ALLOWED_SCOPES: [&str; 2] = ["cert:read", "cert:issue"];

#[openapi(tag = "Service Accounts")]
#[post("/users/<id>/service-accounts", format = "json", data = "<payload>")]
/// Create a service account owned by a user. Requires admin. Returns the secret once.
pub(crate) async fn create_service_account(
    state: &State<AppState>,
    id: i64,
    payload: Json<CreateServiceAccountRequest>,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<ServiceAccountCreated>, ApiError> {
    // Validate scopes
    for scope in &payload.scopes {
        if !ALLOWED_SCOPES.contains(&scope.as_str()) {
            return Err(ApiError::BadRequest(format!("Unknown scope: {scope}")));
        }
    }
    // Owner must exist
    state.db.get_user(id).await.map_err(|_| ApiError::NotFound(None))?;

    let (client_id, secret) = generate_credentials();
    let secret_hash = hash_secret(&secret)?;
    let now = chrono::Utc::now().timestamp_millis();

    let sa = ServiceAccount {
        id: -1,
        name: payload.name.clone(),
        client_id: client_id.clone(),
        secret_hash,
        user_id: id,
        scopes: payload.scopes.clone(),
        created_at: now,
        last_used_at: None,
        revoked: false,
    };
    let saved = state.db.insert_service_account(sa).await?;

    Ok(Json(ServiceAccountCreated {
        id: saved.id,
        name: saved.name,
        client_id,
        secret,
        scopes: saved.scopes,
    }))
}

#[openapi(tag = "Service Accounts")]
#[get("/users/<id>/service-accounts")]
/// List a user's service accounts (no secrets). Requires admin.
pub(crate) async fn list_service_accounts(
    state: &State<AppState>,
    id: i64,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<Vec<ServiceAccount>>, ApiError> {
    let accounts = state.db.list_service_accounts_by_user(id).await?;
    Ok(Json(accounts))
}

#[openapi(tag = "Service Accounts")]
#[delete("/service-accounts/<sid>")]
/// Revoke a service account. Requires admin.
pub(crate) async fn revoke_service_account(
    state: &State<AppState>,
    sid: i64,
    _authentication: AuthenticatedPrivileged,
) -> Result<(), ApiError> {
    state.db.revoke_service_account(sid).await?;
    Ok(())
}
```

Note: `ServiceAccount` derives `Serialize` with `secret_hash` marked `#[serde(skip)]`, so the list response never includes the hash.

- [ ] **Step 5: Mount the three routes**

In `backend/src/lib.rs`, add to EVERY `openapi_get_routes![ ... ]` list: `create_service_account,`, `list_service_accounts,`, `revoke_service_account,`.

- [ ] **Step 6: Run the tests**

Run: `cd backend && cargo test --test integration_tests service_account 2>&1 | tail -20`
Expected: PASS (create/list/revoke round-trip, unknown-scope 400, admin-only 403).

- [ ] **Step 7: Full suite**

Run: `cd backend && cargo test 2>&1 | tail -8`
Expected: green except pre-existing `test_ssh_revocation_and_krl`.

- [ ] **Step 8: Commit**

```bash
cd backend && git add src/data/api.rs src/api.rs src/lib.rs tests/api/api_test_service_accounts.rs
git commit -m "feat(auth): admin service-account management endpoints"
```

---

### Task 5: Scope-gated issue and read for service tokens

**Files:**
- Modify: `backend/src/api.rs` (`create_user_certificate`, `get_certificates`, `download_certificate`, `fetch_certificate_password`)
- Test: `backend/tests/api/api_test_service_accounts.rs`

**Interfaces:**
- Consumes: `Claims::is_service`, `Claims::has_scope`, `Authenticated`.
- Produces: scope enforcement on issue/read; service issuance bound to owner.

- [ ] **Step 1: Write the failing tests**

Append to `backend/tests/api/api_test_service_accounts.rs`. Reuse `create_service_account`. The helper exchanges and returns a Bearer token:

```rust
use rocket::http::Header;

async fn token_for(client: &VaulTLSClient, client_id: &str, secret: &str) -> String {
    let resp = client
        .post("/auth/token")
        .header(ContentType::JSON)
        .body(format!(r#"{{"client_id":"{client_id}","secret":"{secret}"}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let v: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    v["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn service_read_requires_scope() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await;
    // account WITHOUT cert:read
    let created = create_service_account(&admin, 1, "noread", &["cert:issue"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;

    let resp = admin
        .get("/certificates")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn service_with_read_scope_lists_owner_certs() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await;
    let created = create_service_account(&admin, 1, "reader", &["cert:read"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;

    let resp = admin
        .get("/certificates")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    Ok(())
}

#[tokio::test]
async fn service_issue_binds_to_owner() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await;
    // second user (id 2) so we can attempt to issue for someone else
    admin.create_user().await?;
    // service owned by user 1, with cert:issue
    let created = create_service_account(&admin, 1, "issuer", &["cert:issue"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;

    // Try to issue for user 2 — must be forced to owner (user 1)
    let body = r#"{"cert_name":{"cn":"svc-cert"},"user_id":2,"system_generated_password":false,"cert_type":0}"#;
    let resp = admin
        .post("/certificates")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let v: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(v["user_id"].as_i64().unwrap(), 1, "service must issue for its owner, not user 2");
    Ok(())
}
```

Note: `create_user` helper exists in the test client and creates user id 2. The issue body uses minimal required `CreateUserCertificateRequest` fields; if the helper or request shape differs, mirror `create_client_cert`'s body in `test_client.rs`.

- [ ] **Step 2: Run to verify failure**

Run: `cd backend && cargo test --test integration_tests "service_read_requires_scope" "service_with_read_scope" "service_issue_binds" 2>&1 | tail -25`
Expected: FAIL — read currently allows any authenticated token (no scope gate); issue still requires Admin guard (a User-role service token gets 403 from `AuthenticatedPrivileged`).

- [ ] **Step 3: Gate read endpoints on `cert:read` for service tokens**

In `get_certificates`, at the top of the body (after the guard binds `authentication`), add:

```rust
    if authentication.claims.is_service() && !authentication.claims.has_scope("cert:read") {
        return Err(ApiError::Forbidden(None));
    }
```

Add the same guard line at the top of `download_certificate` and `fetch_certificate_password` (each already has `authentication: Authenticated`). The existing ownership checks (`certificate.user_id != authentication.claims.id`) already restrict a service to its owner's certs because the service token's `id` IS the owner.

- [ ] **Step 4: Convert issue to `Authenticated` + scope, force owner**

Replace `create_user_certificate`'s signature guard and add scope/owner logic. Change the parameter from `_authentication: AuthenticatedPrivileged` to `authentication: Authenticated`, take `payload` as mutable, and insert the authorization block before any use of `payload`:

```rust
pub(crate) async fn create_user_certificate(
    state: &State<AppState>,
    payload: Json<CreateUserCertificateRequest>,
    authentication: Authenticated,
) -> Result<Json<Certificate>, ApiError> {
    let mut payload = payload.into_inner();

    // Authorization: human Admin, or service with cert:issue (bound to its owner).
    if authentication.claims.is_service() {
        if !authentication.claims.has_scope("cert:issue") {
            return Err(ApiError::Forbidden(None));
        }
        payload.user_id = authentication.claims.id; // force owner; never issue for another user
    } else if authentication.claims.role != UserRole::Admin {
        return Err(ApiError::Forbidden(None));
    }

    debug!(cert_name=?payload.cert_name, "Creating certificate");
    // ... rest of the existing body, but every `payload.field` now refers to the
    // owned `payload` (no `.into_inner()` elsewhere). The existing body used
    // `&payload` and `payload.field`; with an owned `payload` those still compile.
```

Keep the remainder of the function unchanged except that `payload` is now the owned value (remove any later `payload.into_inner()` if present; the original took `Json<...>` directly and used `&payload`/`payload.field`, which work on the owned binding). `Authenticated` import already exists in `api.rs`.

- [ ] **Step 5: Run the tests**

Run: `cd backend && cargo test --test integration_tests "service_read_requires_scope" "service_with_read_scope" "service_issue_binds" 2>&1 | tail -25`
Expected: PASS.

- [ ] **Step 6: Full suite (human flows must be intact)**

Run: `cd backend && cargo test 2>&1 | tail -8`
Expected: green except pre-existing `test_ssh_revocation_and_krl`. In particular `test_privilege_escalation` and certificate-creation tests (human Admin issues, human User forbidden) must still pass.

- [ ] **Step 7: Commit**

```bash
cd backend && git add src/api.rs tests/api/api_test_service_accounts.rs
git commit -m "feat(auth): scope-gated issue/read for service tokens, owner-bound issuance"
```

---

### Task 6: Frontend types, API module, Pinia store

**Files:**
- Create: `frontend/src/types/ServiceAccount.ts`
- Create: `frontend/src/api/serviceAccounts.ts`
- Create: `frontend/src/stores/serviceAccounts.ts`

**Interfaces:**
- Consumes: `ApiClient.{get,post,delete}` (`baseURL = origin + '/api'`, `withCredentials: true`).
- Produces:
  - Types `ServiceAccount`, `CreateServiceAccountRequest`, `ServiceAccountCreated`, `SERVICE_SCOPES`.
  - API `listServiceAccounts(userId)`, `createServiceAccount(userId, req)`, `revokeServiceAccount(id)`.
  - Store `useServiceAccountStore` with `accounts`, `loading`, `error`, `lastCreated`, actions `fetchForUser`, `create`, `revoke`, `clearLastCreated`.

- [ ] **Step 1: Create the types**

`frontend/src/types/ServiceAccount.ts`:

```typescript
export const SERVICE_SCOPES = ['cert:read', 'cert:issue'] as const
export type ServiceScope = (typeof SERVICE_SCOPES)[number]

export interface ServiceAccount {
  id: number
  name: string
  client_id: string
  user_id: number
  scopes: string[]
  created_at: number
  last_used_at: number | null
  revoked: boolean
}

export interface CreateServiceAccountRequest {
  name: string
  scopes: string[]
}

export interface ServiceAccountCreated {
  id: number
  name: string
  client_id: string
  secret: string
  scopes: string[]
}
```

- [ ] **Step 2: Create the API module**

`frontend/src/api/serviceAccounts.ts`:

```typescript
import ApiClient from './ApiClient'
import type {
  ServiceAccount,
  CreateServiceAccountRequest,
  ServiceAccountCreated,
} from '@/types/ServiceAccount'

export const listServiceAccounts = async (userId: number): Promise<ServiceAccount[]> => {
  return await ApiClient.get<ServiceAccount[]>(`/users/${userId}/service-accounts`)
}

export const createServiceAccount = async (
  userId: number,
  req: CreateServiceAccountRequest,
): Promise<ServiceAccountCreated> => {
  return await ApiClient.post<ServiceAccountCreated>(`/users/${userId}/service-accounts`, req)
}

export const revokeServiceAccount = async (id: number): Promise<void> => {
  await ApiClient.delete<void>(`/service-accounts/${id}`)
}
```

- [ ] **Step 3: Create the store**

`frontend/src/stores/serviceAccounts.ts`:

```typescript
import { defineStore } from 'pinia'
import axios from 'axios'
import type {
  ServiceAccount,
  CreateServiceAccountRequest,
  ServiceAccountCreated,
} from '@/types/ServiceAccount'
import {
  listServiceAccounts,
  createServiceAccount,
  revokeServiceAccount,
} from '@/api/serviceAccounts'

export const useServiceAccountStore = defineStore('serviceAccount', {
  state: () => ({
    accounts: [] as ServiceAccount[],
    loading: false,
    error: null as string | null,
    lastCreated: null as ServiceAccountCreated | null,
  }),

  actions: {
    async fetchForUser(userId: number): Promise<void> {
      this.loading = true
      this.error = null
      try {
        this.accounts = await listServiceAccounts(userId)
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to load service accounts: ' + err.response?.data?.error
          : 'Failed to load service accounts'
        console.error(err)
      } finally {
        this.loading = false
      }
    },

    async create(userId: number, req: CreateServiceAccountRequest): Promise<boolean> {
      this.loading = true
      this.error = null
      try {
        this.lastCreated = await createServiceAccount(userId, req)
        await this.fetchForUser(userId)
        return true
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to create service account: ' + err.response?.data?.error
          : 'Failed to create service account'
        console.error(err)
        return false
      } finally {
        this.loading = false
      }
    },

    async revoke(userId: number, id: number): Promise<void> {
      this.loading = true
      this.error = null
      try {
        await revokeServiceAccount(id)
        await this.fetchForUser(userId)
      } catch (err) {
        this.error = axios.isAxiosError(err)
          ? 'Failed to revoke service account: ' + err.response?.data?.error
          : 'Failed to revoke service account'
        console.error(err)
      } finally {
        this.loading = false
      }
    },

    clearLastCreated(): void {
      this.lastCreated = null
    },
  },
})
```

- [ ] **Step 4: Verify the frontend builds**

Run: `cd frontend && npm run build 2>&1 | tail -20`
Expected: build succeeds (unused-module warnings are fine — consumed in Task 7).

- [ ] **Step 5: Commit**

```bash
cd frontend && git add src/types/ServiceAccount.ts src/api/serviceAccounts.ts src/stores/serviceAccounts.ts
git commit -m "feat(ui): service-account types, API module, Pinia store"
```

---

### Task 7: ServiceAccountsModal + Users-tab integration + i18n

**Files:**
- Create: `frontend/src/components/ServiceAccountsModal.vue`
- Modify: `frontend/src/components/UserTab.vue`
- Modify: `frontend/src/locales/en.json`, `frontend/src/locales/es.json`

**Interfaces:**
- Consumes: `useServiceAccountStore`, `BaseModal`, `SERVICE_SCOPES`, `User`.

- [ ] **Step 1: Add i18n keys**

In `frontend/src/locales/en.json`, add a top-level `"serviceAccounts"` block (sibling of `"users"`):

```json
"serviceAccounts": {
  "title": "Service Accounts",
  "subtitle": "API access for {name}",
  "openButton": "Service accounts",
  "create": "Create service account",
  "name": "Name",
  "scopes": "Scopes",
  "clientId": "Client ID",
  "created": "Created",
  "lastUsed": "Last used",
  "never": "never",
  "status": "Status",
  "active": "Active",
  "revoked": "Revoked",
  "revoke": "Revoke",
  "noAccounts": "No service accounts yet.",
  "secretTitle": "Save this secret now",
  "secretWarning": "This secret is shown only once. Store it securely — it cannot be retrieved later.",
  "copy": "Copy",
  "copied": "Copied",
  "scopeCertRead": "Read & download certificates (cert:read)",
  "scopeCertIssue": "Issue certificates (cert:issue)"
}
```

In `frontend/src/locales/es.json`, add the same block translated:

```json
"serviceAccounts": {
  "title": "Cuentas de servicio",
  "subtitle": "Acceso API para {name}",
  "openButton": "Cuentas de servicio",
  "create": "Crear cuenta de servicio",
  "name": "Nombre",
  "scopes": "Permisos",
  "clientId": "Client ID",
  "created": "Creada",
  "lastUsed": "Último uso",
  "never": "nunca",
  "status": "Estado",
  "active": "Activa",
  "revoked": "Revocada",
  "revoke": "Revocar",
  "noAccounts": "Aún no hay cuentas de servicio.",
  "secretTitle": "Guarda este secreto ahora",
  "secretWarning": "Este secreto se muestra solo una vez. Guárdalo de forma segura — no se puede recuperar después.",
  "copy": "Copiar",
  "copied": "Copiado",
  "scopeCertRead": "Leer y descargar certificados (cert:read)",
  "scopeCertIssue": "Emitir certificados (cert:issue)"
}
```

- [ ] **Step 2: Create `ServiceAccountsModal.vue`**

`frontend/src/components/ServiceAccountsModal.vue`:

```vue
<template>
  <BaseModal
    :visible="visible"
    :title="$t('serviceAccounts.title')"
    hideFooter
    width="640px"
    @update:visible="(v: boolean) => emit('update:visible', v)"
    @cancel="onClose"
  >
    <p class="vt-sub">{{ $t('serviceAccounts.subtitle', { name: user?.name }) }}</p>

    <!-- One-time secret panel -->
    <div v-if="store.lastCreated" class="vt-secret-panel">
      <strong>{{ $t('serviceAccounts.secretTitle') }}</strong>
      <p class="vt-warn">{{ $t('serviceAccounts.secretWarning') }}</p>
      <div class="vt-secret-row">
        <span class="vt-mono">{{ $t('serviceAccounts.clientId') }}:</span>
        <code>{{ store.lastCreated.client_id }}</code>
        <button class="vt-icon-btn" @click="copy(store.lastCreated.client_id, 'cid')">
          <i :class="copied === 'cid' ? 'pi pi-check' : 'pi pi-copy'" />
        </button>
      </div>
      <div class="vt-secret-row">
        <span class="vt-mono">secret:</span>
        <code>{{ store.lastCreated.secret }}</code>
        <button class="vt-icon-btn" @click="copy(store.lastCreated.secret, 'secret')">
          <i :class="copied === 'secret' ? 'pi pi-check' : 'pi pi-copy'" />
        </button>
      </div>
      <Button :label="$t('common.save')" size="small" @click="store.clearLastCreated()" />
    </div>

    <!-- Create form -->
    <div v-else class="vt-create-form">
      <InputText v-model="newName" :placeholder="$t('serviceAccounts.name')" class="vt-input-full" />
      <label class="vt-checkbox-label">
        <input v-model="scopeRead" type="checkbox" class="vt-checkbox" />
        {{ $t('serviceAccounts.scopeCertRead') }}
      </label>
      <label class="vt-checkbox-label">
        <input v-model="scopeIssue" type="checkbox" class="vt-checkbox" />
        {{ $t('serviceAccounts.scopeCertIssue') }}
      </label>
      <Button
        :label="$t('serviceAccounts.create')"
        icon="pi pi-plus"
        :disabled="!newName || (!scopeRead && !scopeIssue) || store.loading"
        @click="onCreate"
      />
    </div>

    <div v-if="store.error" class="vt-error">{{ store.error }}</div>

    <!-- List -->
    <DataTable :value="store.accounts" dataKey="id" class="vt-table">
      <Column field="name" :header="$t('serviceAccounts.name')" />
      <Column field="client_id" :header="$t('serviceAccounts.clientId')" />
      <Column :header="$t('serviceAccounts.scopes')">
        <template #body="{ data }">
          <Tag v-for="s in data.scopes" :key="s" :value="s" severity="secondary" />
        </template>
      </Column>
      <Column :header="$t('serviceAccounts.status')">
        <template #body="{ data }">
          <Tag
            :value="data.revoked ? $t('serviceAccounts.revoked') : $t('serviceAccounts.active')"
            :severity="data.revoked ? 'danger' : 'success'"
          />
        </template>
      </Column>
      <Column :header="$t('common.actions')">
        <template #body="{ data }">
          <Button
            v-if="!data.revoked"
            :label="$t('serviceAccounts.revoke')"
            icon="pi pi-ban"
            severity="danger"
            outlined
            size="small"
            @click="onRevoke(data.id)"
          />
        </template>
      </Column>
      <template #empty>
        <div class="vt-empty">{{ $t('serviceAccounts.noAccounts') }}</div>
      </template>
    </DataTable>
  </BaseModal>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import BaseModal from '@/components/BaseModal.vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { useServiceAccountStore } from '@/stores/serviceAccounts'
import type { User } from '@/types/User'

const props = defineProps<{ visible: boolean; user: User | null }>()
const emit = defineEmits<{ 'update:visible': [boolean] }>()

const store = useServiceAccountStore()
const newName = ref('')
const scopeRead = ref(true)
const scopeIssue = ref(false)
const copied = ref<string | null>(null)

watch(
  () => props.visible,
  (open) => {
    if (open && props.user) {
      store.clearLastCreated()
      newName.value = ''
      scopeRead.value = true
      scopeIssue.value = false
      store.fetchForUser(props.user.id)
    }
  },
)

const onCreate = async () => {
  if (!props.user) return
  const scopes: string[] = []
  if (scopeRead.value) scopes.push('cert:read')
  if (scopeIssue.value) scopes.push('cert:issue')
  await store.create(props.user.id, { name: newName.value, scopes })
  newName.value = ''
}

const onRevoke = async (id: number) => {
  if (props.user) await store.revoke(props.user.id, id)
}

const onClose = () => {
  store.clearLastCreated()
  emit('update:visible', false)
}

const copy = async (text: string, which: string) => {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = which
    setTimeout(() => (copied.value = null), 1500)
  } catch (err) {
    console.error('Failed to copy to clipboard: ', err)
  }
}
</script>

<style scoped>
.vt-create-form { display: flex; flex-direction: column; gap: 12px; margin: 12px 0; }
.vt-input-full { width: 100%; }
.vt-checkbox-label { display: flex; align-items: center; gap: 8px; font-size: 14px; }
.vt-secret-panel { border: 1px solid var(--vt-border); border-radius: 8px; padding: 14px; margin: 12px 0; }
.vt-secret-row { display: flex; align-items: center; gap: 8px; margin: 6px 0; }
.vt-secret-row code { background: rgba(127,127,127,0.12); padding: 2px 6px; border-radius: 4px; word-break: break-all; }
.vt-warn { color: var(--vt-muted); font-size: 13px; }
.vt-icon-btn { background: transparent; border: none; cursor: pointer; color: var(--vt-muted); }
.vt-error { background: var(--vt-err); color: #fff; padding: 8px 12px; border-radius: 6px; margin: 8px 0; font-size: 13px; }
.vt-empty { text-align: center; padding: 16px; color: var(--vt-muted); font-style: italic; }
.vt-sub { color: var(--vt-muted); font-size: 13px; margin-bottom: 8px; }
.vt-table { margin-top: 12px; }
</style>
```

- [ ] **Step 3: Wire the modal into `UserTab.vue`**

In the row-actions `<div class="vt-row-actions">` (template), add a button before the Edit button:

```vue
            <Button
              :id="'UserServiceAccountsButton-' + data.id"
              :label="$t('serviceAccounts.openButton')"
              icon="pi pi-key"
              severity="secondary"
              outlined
              size="small"
              @click="openServiceAccounts(data)"
            />
```

Add the modal component just before the closing `</div>` of the template (next to the other `<BaseModal>` dialogs):

```vue
    <ServiceAccountsModal
      v-model:visible="isServiceAccountsVisible"
      :user="serviceAccountsUser"
    />
```

In `<script setup>`, add the import and state:

```typescript
import ServiceAccountsModal from '@/components/ServiceAccountsModal.vue'
// ...
const isServiceAccountsVisible = ref(false)
const serviceAccountsUser = ref<User | null>(null)
const openServiceAccounts = (user: User) => {
  serviceAccountsUser.value = user
  isServiceAccountsVisible.value = true
}
```

- [ ] **Step 4: Build the frontend**

Run: `cd frontend && npm run build 2>&1 | tail -20`
Expected: build succeeds.

- [ ] **Step 5: Lint/type-check if the project has it**

Run: `cd frontend && npm run type-check 2>&1 | tail -20` (skip if the script does not exist; the build already type-checks via vue-tsc in most setups)
Expected: no type errors in the new files.

- [ ] **Step 6: Commit**

```bash
cd frontend && git add src/components/ServiceAccountsModal.vue src/components/UserTab.vue src/locales/en.json src/locales/es.json
git commit -m "feat(ui): service-accounts management modal in Users section"
```

---

## Self-Review

**Spec coverage:**
- Migration + model + secret hashing + DB CRUD → Task 1. ✅
- Claims `service` block, `generate_service_token`, Bearer acceptance, stateless (JTI skip), scope helpers → Task 2. ✅
- `POST /auth/token` (uniform 401, last_used) → Task 3. ✅
- Admin management endpoints (create returns secret once, list no secret, revoke) → Task 4. ✅
- Scope-gated issue (`cert:issue`, owner-bound) + read (`cert:read`) → Task 5. ✅
- Frontend types/api/store → Task 6; modal + Users integration + i18n (en/es) → Task 7. ✅
- Human cookie flow unchanged (verified by full suite incl. `test_privilege_escalation`) → Tasks 2,5. ✅

**Placeholder scan:** No TBD/TODO. The `create_user_certificate` edit in Task 5 references "rest of the existing body" — this is an in-place modification of an existing function, with the exact guard/owner block given verbatim and an explicit note that the remaining body is unchanged; not a placeholder for new logic.

**Type consistency:** `ServiceAccount`, `ServiceClaims`, `ServiceTokenRequest/Response`, `CreateServiceAccountRequest`, `ServiceAccountCreated`, `generate_service_token(jwt_key, owner_user_id, account_id, scopes)`, `has_scope`/`is_service`, DB method names, scopes CSV↔Vec, and the `cert:read`/`cert:issue` literals are consistent across backend tasks and mirrored in the frontend types. The frontend `ServiceAccount` fields match the backend serialized shape (secret_hash skipped).
