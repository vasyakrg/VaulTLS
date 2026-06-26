# Client-facing API (Scalar, cert validation, CA polish) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the VaulTLS HTTP API friendlier for programmatic clients via a self-hosted Scalar API reference, a public certificate-validation endpoint keyed by serial number, and polish of the public CA download endpoints.

**Architecture:** Three backend slices shipping together (frontend untouched). Reuses the existing `rocket_okapi`/`schemars` OpenAPI generation. A prerequisite slice fills `user_certificates.serial_hex` (currently only ACME-issued certs set it) for both new and existing certs, so validation actually finds normally-issued certs.

**Tech Stack:** Rust, Rocket 0.5.1, rocket_okapi 0.9, schemars 0.8, rusqlite/SQLCipher, openssl 0.10, `scalar_api_reference` 0.2.2.

## Global Constraints

- Backend only. Do **not** touch `frontend/`.
- No DB migration: `serial_hex`, `created_on`, `valid_until`, `revoked_at`, `ca_id` already exist on `user_certificates` (`serial_hex` indexed by `idx_user_certificates_serial_hex`).
- `serial_hex` format is **lowercase hex, no separators**: `serial.iter().map(|b| format!("{b:02x}")).collect::<String>()`. New code MUST match this exactly (ACME already uses it) or lookups silently miss.
- `CA.cert` is stored as **DER**. PEM is produced via `get_tls_pem(&ca)` (`X509::from_der().to_pem()`).
- The validation endpoint and the CA endpoints are **public** (no auth guard).
- Validation response MUST NOT leak CN/SAN/owner — only status + timestamps + ca_id.
- CA download default stays **PEM** for TLS — never rely on `DataFormat::default()` (which is `DER`) for the default branch, or current behaviour regresses.
- Timestamps are epoch **milliseconds** (matches existing columns). Current time: `chrono::Utc::now().timestamp_millis()`.
- Run the backend test suite with `cargo test` from `backend/`. Existing tests must stay green.
- New integration tests live in `backend/tests/api/` and must be registered in `backend/tests/api/mod.rs`.

---

### Task 1: Certificate status types, pure status function, and DB lookup

**Files:**
- Modify: `backend/src/data/enums.rs` (add `CertStatus` enum)
- Modify: `backend/src/data/api.rs` (add `CertStatusResponse`, `compute_cert_status`, and its unit tests)
- Modify: `backend/src/db.rs` (add `CertStatusRow` + `get_cert_status_by_serial_hex`)

**Interfaces:**
- Produces:
  - `pub enum CertStatus { Valid, Revoked, Expired, NotYetValid, Unknown }` (in `data/enums.rs`)
  - `pub fn compute_cert_status(now_ms: i64, created_on: i64, valid_until: i64, revoked_at: Option<i64>) -> CertStatus` (in `data/api.rs`)
  - `pub struct CertStatusResponse { serial: String, status: CertStatus, not_before: Option<i64>, not_after: Option<i64>, revoked_at: Option<i64>, ca_id: Option<i64> }` (in `data/api.rs`)
  - `pub struct CertStatusRow { created_on: i64, valid_until: i64, revoked_at: Option<i64>, ca_id: Option<i64> }` and `async fn get_cert_status_by_serial_hex(&self, serial_hex: String) -> Result<Option<CertStatusRow>>` (in `db.rs`)

- [ ] **Step 1: Add the `CertStatus` enum**

In `backend/src/data/enums.rs`, after the `DataFormat` enum (around line 170), add. `Serialize`/`JsonSchema` are already imported and used in this file:

```rust
#[derive(serde::Serialize, rocket_okapi::JsonSchema, Clone, Debug, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    Valid,
    Revoked,
    Expired,
    NotYetValid,
    Unknown,
}
```

- [ ] **Step 2: Write the failing unit test for `compute_cert_status`**

In `backend/src/data/api.rs`, at the end of the file, add a test module. Adjust the `use super::*` path only if `compute_cert_status`/`CertStatus` are not in scope:

```rust
#[cfg(test)]
mod cert_status_tests {
    use super::compute_cert_status;
    use crate::data::enums::CertStatus;

    #[test]
    fn valid_when_within_window_and_not_revoked() {
        // now between created_on and valid_until, not revoked
        assert_eq!(compute_cert_status(150, 100, 200, None), CertStatus::Valid);
    }

    #[test]
    fn revoked_takes_precedence_over_window() {
        // revoked_at set, even though now is within the validity window
        assert_eq!(compute_cert_status(150, 100, 200, Some(140)), CertStatus::Revoked);
    }

    #[test]
    fn expired_when_now_past_valid_until() {
        assert_eq!(compute_cert_status(250, 100, 200, None), CertStatus::Expired);
    }

    #[test]
    fn not_yet_valid_when_now_before_created_on() {
        assert_eq!(compute_cert_status(50, 100, 200, None), CertStatus::NotYetValid);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd backend && cargo test --lib compute_cert_status 2>&1 | tail -20`
Expected: FAIL — `cannot find function compute_cert_status`.

- [ ] **Step 4: Implement `compute_cert_status` and `CertStatusResponse`**

In `backend/src/data/api.rs`, add near the other response structs (ensure `use crate::data::enums::CertStatus;` is present at the top of the file alongside the existing `enums` imports):

```rust
/// Pure status decision. Order matters: revocation first, then validity window.
pub fn compute_cert_status(
    now_ms: i64,
    created_on: i64,
    valid_until: i64,
    revoked_at: Option<i64>,
) -> CertStatus {
    if revoked_at.is_some() {
        CertStatus::Revoked
    } else if now_ms > valid_until {
        CertStatus::Expired
    } else if now_ms < created_on {
        CertStatus::NotYetValid
    } else {
        CertStatus::Valid
    }
}

#[derive(serde::Serialize, rocket_okapi::JsonSchema)]
pub struct CertStatusResponse {
    pub serial: String,
    pub status: CertStatus,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub revoked_at: Option<i64>,
    pub ca_id: Option<i64>,
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd backend && cargo test --lib compute_cert_status 2>&1 | tail -20`
Expected: PASS (4 tests).

- [ ] **Step 6: Add the DB lookup `get_cert_status_by_serial_hex`**

In `backend/src/db.rs`, add the row struct near the top (after imports) and the method inside the `impl VaulTLSDB` block (next to `get_cert_id_by_serial_hex`, ~line 926). This query, unlike `get_cert_id_by_serial_hex`, does NOT exclude revoked rows:

```rust
pub(crate) struct CertStatusRow {
    pub created_on: i64,
    pub valid_until: i64,
    pub revoked_at: Option<i64>,
    pub ca_id: Option<i64>,
}

impl VaulTLSDB {
    pub(crate) async fn get_cert_status_by_serial_hex(&self, serial_hex: String) -> Result<Option<CertStatusRow>> {
        db_do!(self.pool, |conn: &Connection| {
            let result = conn.query_row(
                "SELECT created_on, valid_until, revoked_at, ca_id FROM user_certificates WHERE serial_hex = ?1",
                params![serial_hex],
                |row| Ok(CertStatusRow {
                    created_on: row.get(0)?,
                    valid_until: row.get(1)?,
                    revoked_at: row.get(2)?,
                    ca_id: row.get(3)?,
                }),
            );
            match result {
                Ok(r) => Ok(Some(r)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        })
    }
}
```

Note: place `pub(crate) struct CertStatusRow { ... }` at module level (not inside `impl`); the `impl VaulTLSDB { ... }` shown is to indicate the method goes in an impl block — add the method to the existing `impl VaulTLSDB`, do not open a second one if it causes duplicate-method issues; a second `impl VaulTLSDB` block is legal in Rust, so either is fine.

- [ ] **Step 7: Verify it compiles**

Run: `cd backend && cargo build 2>&1 | tail -20`
Expected: builds (warnings about unused `get_cert_status_by_serial_hex`/`CertStatusResponse` are acceptable — consumed in Task 3).

- [ ] **Step 8: Commit**

```bash
cd backend && git add src/data/enums.rs src/data/api.rs src/db.rs
git commit -m "feat(api): cert status types, pure status fn, serial lookup"
```

---

### Task 2: Populate `serial_hex` on issuance and backfill existing certs

**Files:**
- Modify: `backend/src/api.rs` (`create_user_certificate`, after `insert_user_cert`)
- Modify: `backend/src/db.rs` (add `backfill_serials`)
- Modify: `backend/src/lib.rs` (call `backfill_serials` during startup)

**Interfaces:**
- Consumes: `Certificate::get_serial() -> Result<Vec<u8>>`, `VaulTLSDB::set_cert_serial(id, serial_hex)`, `VaulTLSDB::get_user_cert_by_id(id)`.
- Produces: `async fn backfill_serials(&self) -> Result<()>` (in `db.rs`).

- [ ] **Step 1: Add `backfill_serials` to the DB layer**

In `backend/src/db.rs`, add to an `impl VaulTLSDB` block. It collects ids with a missing/empty serial, then computes and stores each:

```rust
pub(crate) async fn backfill_serials(&self) -> Result<()> {
    let ids: Vec<i64> = db_do!(self.pool, |conn: &Connection| {
        let mut stmt = conn.prepare(
            "SELECT id FROM user_certificates WHERE serial_hex IS NULL OR serial_hex = ''"
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<i64>>>()?)
    });

    for id in ids {
        let cert = self.get_user_cert_by_id(id).await?;
        if let Ok(serial) = cert.get_serial() {
            let serial_hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
            if !serial_hex.is_empty() {
                self.set_cert_serial(id, serial_hex).await?;
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Call backfill during startup**

In `backend/src/lib.rs`, in `create_rocket()`, immediately after `db.fix_password().await.expect("Failed fixing passwords");` (~line 87) add:

```rust
    db.backfill_serials().await.expect("Failed backfilling certificate serials");
```

- [ ] **Step 3: Populate serial on new issuance**

In `backend/src/api.rs`, in `create_user_certificate`, right after the line `cert = state.db.insert_user_cert(cert).await?;` (~line 687) add. `cert` still holds its `data`/`password`, so `get_serial()` works:

```rust
    if let Ok(serial) = cert.get_serial() {
        let serial_hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
        if !serial_hex.is_empty() {
            let _ = state.db.set_cert_serial(cert.id, serial_hex).await;
        }
    }
```

- [ ] **Step 4: Write the failing integration test**

Create `backend/tests/api/api_test_client_api.rs` with this content (this file also hosts Task 3/4/5 tests later). The helper extracts the issued cert's serial from the downloaded PKCS#12 and confirms issuance stored a matching `serial_hex` indirectly via the validate endpoint added in Task 3 — but for THIS task we assert the serial is retrievable from the download and non-empty, proving issuance path runs:

```rust
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use openssl::pkcs12::Pkcs12;
use rocket::http::{ContentType, Status};

/// Extract the lowercase-hex serial from a downloaded PKCS#12 bundle.
fn serial_hex_from_p12(p12: &[u8], password: &str) -> String {
    let parsed = Pkcs12::from_der(p12).unwrap().parse2(password).unwrap();
    let cert = parsed.cert.unwrap();
    let bn = cert.serial_number().to_bn().unwrap().to_vec();
    bn.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn issuance_records_serial() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let cert = client.create_client_cert(None, Some("pw".to_string()), None).await?;

    // Download the issued cert and derive its serial
    let req = client.get(format!("/certificates/{}/download", cert.id));
    let resp = req.dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let p12 = resp.into_bytes().await.unwrap();
    let serial = serial_hex_from_p12(&p12, "pw");
    assert!(!serial.is_empty());

    Ok(())
}
```

- [ ] **Step 5: Register the new test module**

In `backend/tests/api/mod.rs`, add:

```rust
mod api_test_client_api;
```

- [ ] **Step 6: Run the test**

Run: `cd backend && cargo test --test integration_tests issuance_records_serial 2>&1 | tail -25`
Expected: PASS.

- [ ] **Step 7: Run the full suite to confirm no regressions**

Run: `cd backend && cargo test 2>&1 | tail -25`
Expected: all green (pre-existing parallel suite passes).

- [ ] **Step 8: Commit**

```bash
cd backend && git add src/api.rs src/db.rs src/lib.rs tests/api/api_test_client_api.rs tests/api/mod.rs
git commit -m "feat(api): record serial_hex on issuance and backfill existing certs"
```

---

### Task 3: Public certificate-validation endpoint

**Files:**
- Modify: `backend/src/api.rs` (add `validate_certificate` handler)
- Modify: `backend/src/lib.rs` (mount `validate_certificate` in `openapi_get_routes!`)
- Modify: `backend/tests/api/api_test_client_api.rs` (tests)

**Interfaces:**
- Consumes: `get_cert_status_by_serial_hex`, `CertStatusRow`, `compute_cert_status`, `CertStatusResponse`, `CertStatus`.
- Produces: `GET /api/certificates/validate?serial=<hex>` → `Json<CertStatusResponse>`.

- [ ] **Step 1: Write the failing integration tests**

Append to `backend/tests/api/api_test_client_api.rs`:

```rust
#[tokio::test]
async fn validate_reports_valid_then_revoked() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let cert = client.create_client_cert(None, Some("pw".to_string()), None).await?;

    let req = client.get(format!("/certificates/{}/download", cert.id));
    let p12 = req.dispatch().await.into_bytes().await.unwrap();
    let serial = serial_hex_from_p12(&p12, "pw");

    // Valid
    let resp = client.get(format!("/certificates/validate?serial={serial}")).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(v["status"], "valid");
    assert!(v["not_after"].is_number());
    assert!(v["revoked_at"].is_null());
    // No owner/subject leak
    assert!(v.get("name").is_none());
    assert!(v.get("user_id").is_none());

    // Revoke, then expect revoked
    let r = client.post(format!("/certificates/{}/revoke", cert.id)).dispatch().await;
    assert_eq!(r.status(), Status::Ok);
    let resp = client.get(format!("/certificates/validate?serial={serial}")).dispatch().await;
    let v: serde_json::Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(v["status"], "revoked");
    assert!(v["revoked_at"].is_number());

    Ok(())
}

#[tokio::test]
async fn validate_unknown_serial_is_unknown() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/validate?serial=deadbeef").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let v: serde_json::Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(v["status"], "unknown");
    assert!(v["not_after"].is_null());

    Ok(())
}

#[tokio::test]
async fn validate_missing_serial_is_bad_request() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/validate?serial=").dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest);
    Ok(())
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd backend && cargo test --test integration_tests validate_ 2>&1 | tail -25`
Expected: FAIL — route not found (404) / compile error for missing handler once mounted.

- [ ] **Step 3: Implement the handler**

In `backend/src/api.rs`, add (ensure imports: `use crate::data::api::{compute_cert_status, CertStatusResponse};` and `use crate::data::enums::CertStatus;` — match the file's existing import style):

```rust
#[openapi(tag = "Certificates")]
#[get("/certificates/validate?<serial>")]
/// Public: report the status of a certificate by its serial number (lowercase hex).
/// Returns status + validity dates only — never subject/owner.
pub(crate) async fn validate_certificate(
    state: &State<AppState>,
    serial: String,
) -> Result<Json<CertStatusResponse>, ApiError> {
    let normalized: String = serial
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if normalized.is_empty() {
        return Err(ApiError::BadRequest("Missing serial".into()));
    }

    match state.db.get_cert_status_by_serial_hex(normalized.clone()).await? {
        None => Ok(Json(CertStatusResponse {
            serial: normalized,
            status: CertStatus::Unknown,
            not_before: None,
            not_after: None,
            revoked_at: None,
            ca_id: None,
        })),
        Some(row) => {
            let now = chrono::Utc::now().timestamp_millis();
            let status = compute_cert_status(now, row.created_on, row.valid_until, row.revoked_at);
            Ok(Json(CertStatusResponse {
                serial: normalized,
                status,
                not_before: Some(row.created_on),
                not_after: Some(row.valid_until),
                revoked_at: row.revoked_at,
                ca_id: row.ca_id,
            }))
        }
    }
}
```

- [ ] **Step 4: Mount the route**

In `backend/src/lib.rs`, add `validate_certificate,` to the `openapi_get_routes![ ... ]` list (e.g. right after `download_crl,`).

- [ ] **Step 5: Run the tests**

Run: `cd backend && cargo test --test integration_tests validate_ 2>&1 | tail -25`
Expected: PASS (3 tests: valid→revoked, unknown, missing).

- [ ] **Step 6: Full suite**

Run: `cd backend && cargo test 2>&1 | tail -15`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
cd backend && git add src/api.rs src/lib.rs tests/api/api_test_client_api.rs
git commit -m "feat(api): public certificate validation endpoint"
```

---

### Task 4: CA download polish — format selection, file names, MIME

**Files:**
- Modify: `backend/src/data/api.rs` (`DownloadResponse`: add `content_type`, new constructor, use it in `Responder`)
- Modify: `backend/src/api.rs` (`download_current_tls_ca`, `download_ca` accept `?format`)
- Modify: `backend/tests/api/api_test_client_api.rs` (tests)

**Interfaces:**
- Consumes: `DataFormat` (DER/PEM), `get_tls_pem(&CA)`, `CA.cert` (DER bytes), `CAType`.
- Produces: `DownloadResponse::new_typed(content, filename, content_type)`; `DownloadResponse::new` unchanged (defaults to `ContentType::Text`).

- [ ] **Step 1: Extend `DownloadResponse` with a content type**

In `backend/src/data/api.rs`, replace the `DownloadResponse` struct, its `impl`, and the `Responder` impl (lines ~74-100) with. `ContentType` is already imported in this file (used by the existing `Responder`):

```rust
#[derive(Deserialize, Serialize, Debug)]
pub struct DownloadResponse {
    pub content: Vec<u8>,
    pub filename: String,
    #[serde(skip)]
    pub content_type: ContentType,
}

impl DownloadResponse {
    /// Backwards-compatible constructor; defaults to text/plain.
    pub fn new(content: Vec<u8>, filename: &str) -> Self {
        Self { content, filename: filename.to_string(), content_type: ContentType::Text }
    }

    /// Constructor with an explicit content type.
    pub fn new_typed(content: Vec<u8>, filename: &str, content_type: ContentType) -> Self {
        Self { content, filename: filename.to_string(), content_type }
    }
}

impl<'r> Responder<'r, 'static> for DownloadResponse {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .status(Status::Ok)
            .header(self.content_type)
            .header(Header::new(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", self.filename),
            ))
            .sized_body(self.content.len(), Cursor::new(self.content))
            .ok()
    }
}
```

Note: `ContentType` does not implement `Default`; the `#[serde(skip)]` field is fine because `DownloadResponse` is only ever constructed via the two constructors (it is never deserialized at runtime). If the compiler complains that `Deserialize` needs `Default` for the skipped field, replace the derive line with `#[derive(Serialize, Debug)]` (the type is only used as a response, never deserialized).

- [ ] **Step 2: Write the failing tests**

Append to `backend/tests/api/api_test_client_api.rs`:

```rust
#[tokio::test]
async fn ca_download_pem_default_and_der() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Default (PEM)
    let resp = client.get("/certificates/ca/download").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let cd = resp.headers().get_one("Content-Disposition").unwrap_or("").to_string();
    let body = resp.into_bytes().await.unwrap();
    assert!(body.starts_with(b"-----BEGIN CERTIFICATE-----"), "default must be PEM");
    assert!(cd.contains("ca.crt"), "filename should be ca.crt, got {cd}");

    // Explicit DER
    let resp = client.get("/certificates/ca/download?format=der").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let cd = resp.headers().get_one("Content-Disposition").unwrap_or("").to_string();
    let body = resp.into_bytes().await.unwrap();
    assert!(!body.starts_with(b"-----BEGIN"), "DER must not be PEM-armored");
    assert!(cd.contains("ca.der"), "filename should be ca.der, got {cd}");

    Ok(())
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cd backend && cargo test --test integration_tests ca_download_pem_default_and_der 2>&1 | tail -25`
Expected: FAIL (no `format` query support; filename is `ca_certificate.pem`).

- [ ] **Step 4: Add a shared TLS-CA download helper and wire format into endpoints**

In `backend/src/api.rs`, add a helper (ensure `use crate::data::enums::DataFormat;` and `use rocket::http::ContentType;` are imported per the file's style):

```rust
/// Build a download response for a TLS CA in PEM (default) or DER.
fn tls_ca_download(ca: &CA, format: Option<DataFormat>, base_name: &str) -> Result<DownloadResponse, ApiError> {
    match format {
        Some(DataFormat::DER) => Ok(DownloadResponse::new_typed(
            ca.cert.clone(),
            &format!("{base_name}.der"),
            ContentType::new("application", "pkix-cert"),
        )),
        _ => {
            // None or Some(PEM): keep PEM as the default to preserve current behaviour.
            let pem = get_tls_pem(ca).map_err(ApiError::OpenSsl)?;
            Ok(DownloadResponse::new_typed(
                pem,
                &format!("{base_name}.crt"),
                ContentType::new("application", "x-pem-file"),
            ))
        }
    }
}
```

Replace `download_current_tls_ca` and `download_ca` with format-aware versions (leave `download_current_ssh_ca` as-is; SSH has no DER form):

```rust
#[openapi(tag = "Certificates")]
#[get("/certificates/ca/download?<format>")]
/// Download the current TLS CA certificate (PEM by default, or DER via ?format=der).
pub(crate) async fn download_current_tls_ca(
    state: &State<AppState>,
    format: Option<DataFormat>,
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_latest_tls_ca().await?;
    tls_ca_download(&ca, format, "ca")
}

#[openapi(tag = "Certificates")]
#[get("/certificates/ca/<id>/download?<format>")]
/// Download a CA certificate by id (TLS: PEM by default or DER via ?format=der; SSH: .pub).
pub(crate) async fn download_ca(
    state: &State<AppState>,
    id: i64,
    format: Option<DataFormat>,
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_ca_by_id(id).await?;
    match ca.ca_type {
        CAType::TLS => tls_ca_download(&ca, format, &format!("ca_{}", ca.name)),
        CAType::SSH => {
            let pem = get_ssh_pem(&ca).map_err(|e| ApiError::Other(e.to_string()))?;
            Ok(DownloadResponse::new_typed(
                pem,
                &format!("ca_{}.pub", ca.name),
                ContentType::new("application", "octet-stream"),
            ))
        }
    }
}
```

Note: `get_ssh_pem` returns `Result<_, anyhow::Error>`, hence `.map_err(|e| ApiError::Other(e.to_string()))`; `get_tls_pem` returns `Result<_, ErrorStack>`, hence `.map_err(ApiError::OpenSsl)`.

- [ ] **Step 5: Run the test**

Run: `cd backend && cargo test --test integration_tests ca_download_pem_default_and_der 2>&1 | tail -25`
Expected: PASS.

- [ ] **Step 6: Full suite (existing CA-download tests must still pass)**

Run: `cd backend && cargo test 2>&1 | tail -15`
Expected: all green. If an existing test asserted the old filename `ca_certificate.pem`, update that assertion to `ca.crt` as part of this task and note it in the commit.

- [ ] **Step 7: Commit**

```bash
cd backend && git add src/data/api.rs src/api.rs tests/api/api_test_client_api.rs
git commit -m "feat(api): CA download format selection, filenames and MIME types"
```

---

### Task 5: CA fullchain endpoint

**Files:**
- Modify: `backend/src/certs/import.rs` (add `aki_of`)
- Modify: `backend/src/api.rs` (add `download_ca_fullchain`)
- Modify: `backend/src/lib.rs` (mount it)
- Modify: `backend/tests/api/api_test_client_api.rs` (test)

**Interfaces:**
- Consumes: `get_all_ca()`, `CA.cert` (DER), `find_issuing_ca(leaf, &[X509])` (already in `certs/import.rs`), `ski_of`.
- Produces: `pub fn aki_of(cert: &X509) -> Option<Vec<u8>>`; `GET /api/certificates/ca/<id>/fullchain` → PEM chain.

- [ ] **Step 1: Add `aki_of` helper**

In `backend/src/certs/import.rs`, next to `ski_of` (~line 67):

```rust
/// Authority Key Identifier bytes, if present.
pub fn aki_of(cert: &X509) -> Option<Vec<u8>> {
    cert.authority_key_id().map(|a| a.as_slice().to_vec())
}
```

- [ ] **Step 2: Write the failing test**

Append to `backend/tests/api/api_test_client_api.rs`:

```rust
#[tokio::test]
async fn fullchain_internal_ca_is_single_pem() -> Result<()> {
    // The setup wizard creates a self-signed internal TLS CA with id 1.
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/ca/1/fullchain").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_bytes().await.unwrap();
    let text = String::from_utf8_lossy(&body);
    // Self-signed internal CA → exactly one certificate in the chain.
    assert_eq!(text.matches("-----BEGIN CERTIFICATE-----").count(), 1);
    Ok(())
}

#[tokio::test]
async fn fullchain_unknown_ca_is_404() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/ca/9999/fullchain").dispatch().await;
    assert_eq!(resp.status(), Status::NotFound);
    Ok(())
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cd backend && cargo test --test integration_tests fullchain_ 2>&1 | tail -25`
Expected: FAIL (route missing → 404 for both, so `fullchain_internal_ca_is_single_pem` fails on status).

- [ ] **Step 4: Implement the endpoint**

In `backend/src/api.rs`, add (ensure imports: `use openssl::x509::X509;`, `use std::collections::HashSet;`, and `use crate::certs::import::find_issuing_ca;` — match existing style):

```rust
#[openapi(tag = "Certificates")]
#[get("/certificates/ca/<id>/fullchain")]
/// Public: download a TLS CA's full chain (leaf CA first, root last) as one PEM file.
pub(crate) async fn download_ca_fullchain(
    state: &State<AppState>,
    id: i64,
) -> Result<DownloadResponse, ApiError> {
    let ca = state.db.get_ca_by_id(id).await.map_err(|_| ApiError::NotFound(None))?;
    if ca.ca_type != CAType::TLS {
        return Err(ApiError::BadRequest("Fullchain is only available for TLS CAs".into()));
    }

    // Candidate issuers: all stored TLS CAs as X509.
    let all = state.db.get_all_ca().await?;
    let candidates: Vec<X509> = all
        .iter()
        .filter(|c| c.ca_type == CAType::TLS)
        .filter_map(|c| X509::from_der(&c.cert).ok())
        .collect();

    let mut current = X509::from_der(&ca.cert).map_err(ApiError::OpenSsl)?;
    let mut chain_pem: Vec<u8> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    loop {
        // Guard against cycles using the serial number as identity.
        let key = current.serial_number().to_bn()
            .map_err(ApiError::OpenSsl)?.to_vec();
        if !seen.insert(key) {
            break;
        }
        chain_pem.extend_from_slice(&current.to_pem().map_err(ApiError::OpenSsl)?);

        // Stop at a self-signed certificate (subject == issuer).
        let self_signed = current
            .issuer_name()
            .try_cmp(current.subject_name())
            .map(|o| o.is_eq())
            .unwrap_or(false);
        if self_signed {
            break;
        }

        match find_issuing_ca(&current, &candidates) {
            Some(issuer) => current = issuer,
            None => break,
        }
    }

    Ok(DownloadResponse::new_typed(
        chain_pem,
        &format!("fullchain_{}.pem", ca.name),
        ContentType::new("application", "x-pem-file"),
    ))
}
```

- [ ] **Step 5: Mount the route**

In `backend/src/lib.rs`, add `download_ca_fullchain,` to the `openapi_get_routes![ ... ]` list (after `download_ca,`).

- [ ] **Step 6: Run the tests**

Run: `cd backend && cargo test --test integration_tests fullchain_ 2>&1 | tail -25`
Expected: PASS (2 tests).

- [ ] **Step 7: Full suite**

Run: `cd backend && cargo test 2>&1 | tail -15`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
cd backend && git add src/certs/import.rs src/api.rs src/lib.rs tests/api/api_test_client_api.rs
git commit -m "feat(api): CA fullchain download endpoint"
```

---

### Task 6: Replace RapiDoc with self-hosted Scalar

**Files:**
- Modify: `backend/Cargo.toml` (drop `rapidoc` feature, add `scalar_api_reference`)
- Modify: `backend/src/lib.rs` (remove RapiDoc mount/imports; add Scalar routes)
- Modify: `backend/tests/api/api_test_client_api.rs` (tests)

**Interfaces:**
- Consumes: `scalar_api_reference::scalar_html(&serde_json::Value, Option<&str>) -> String`, `scalar_api_reference::get_asset_with_mime(&str) -> Option<(&str, &[u8])>` (or owned bytes — adapt per crate signature, see Step 4).
- Produces: `GET /api/` (Scalar HTML), `GET /api/scalar.js` (embedded bundle). `GET /api/openapi.json` unchanged.

- [ ] **Step 1: Update dependencies**

In `backend/Cargo.toml`, change the `rocket_okapi` line to drop the `rapidoc` feature and add the Scalar crate below it:

```toml
rocket_okapi = { version = "0.9.0", features = ["secrets"] }
scalar_api_reference = "0.2.2"
```

- [ ] **Step 2: Write the failing tests**

Append to `backend/tests/api/api_test_client_api.rs`:

```rust
#[tokio::test]
async fn scalar_docs_served() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    let resp = client.get("/api/").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let html = resp.into_string().await.unwrap();
    assert!(html.contains("/api/openapi.json"), "HTML must reference the spec URL");
    assert!(html.contains("/api/scalar.js"), "HTML must reference the self-hosted bundle");

    let resp = client.get("/api/scalar.js").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    // Spec still served
    let resp = client.get("/api/openapi.json").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    Ok(())
}
```

Note: route paths here are absolute from the client root; the existing helpers call `/server/...` which Rocket resolves under the same client. The docs live under `/api/`, so these calls use the full `/api/...` path. Confirm the test client's base — other tests call `client.get("/server/version")` which maps to `/api/server/version` via mount, so the client base is the app root and `/api/` is correct here.

- [ ] **Step 3: Run to verify failure**

Run: `cd backend && cargo test --test integration_tests scalar_docs_served 2>&1 | tail -25`
Expected: FAIL — `/api/scalar.js` is 404 (RapiDoc still mounted at `/api/`).

- [ ] **Step 4: Swap RapiDoc for Scalar in `lib.rs`**

Remove the RapiDoc import line (`use rocket_okapi::rapidoc::{...};`) and remove the entire `.mount("/api", make_rapidoc(&RapiDocConfig { ... }))` block.

Add two plain Rocket routes (not `#[openapi]` — the docs UI itself need not appear in the spec). Place them near the top-level handlers in `lib.rs` (or in `api.rs` and import them):

```rust
use rocket::response::content::RawHtml;
use rocket::http::ContentType;

#[get("/")]
fn scalar_ui() -> RawHtml<String> {
    let config = serde_json::json!({
        "url": "/api/openapi.json",
        "theme": "purple"
    });
    RawHtml(scalar_api_reference::scalar_html(&config, Some("/api/scalar.js")))
}

#[get("/scalar.js")]
fn scalar_js() -> Option<(ContentType, Vec<u8>)> {
    let (mime, content) = scalar_api_reference::get_asset_with_mime("scalar.js")?;
    let ct = ContentType::parse_flexible(mime).unwrap_or(ContentType::JavaScript);
    Some((ct, content.to_vec()))
}
```

Then mount them on `/api` (replacing the removed RapiDoc mount):

```rust
.mount("/api", routes![scalar_ui, scalar_js])
```

Adapt to the actual crate signatures: if `get_asset_with_mime` returns owned `(String, Vec<u8>)`, drop the `.to_vec()` and `&`; if `scalar_html` takes the config by value, pass `config` not `&config`. Run `cargo build` and follow the compiler. The crate's documented Rust usage is:
`let html = scalar_html(&configuration, Some("/custom-scalar.js"));` and
`if let Some((mime_type, content)) = get_asset_with_mime("scalar.js") { ... }`.

- [ ] **Step 5: Build and run the test**

Run: `cd backend && cargo build 2>&1 | tail -20 && cargo test --test integration_tests scalar_docs_served 2>&1 | tail -25`
Expected: builds; test PASSES.

- [ ] **Step 6: Full suite**

Run: `cd backend && cargo test 2>&1 | tail -15`
Expected: all green.

- [ ] **Step 7: Manual smoke (optional but recommended)**

Run the app locally (docker compose or `cargo run`) and open `/api/` — confirm Scalar renders the API reference and no network calls go to an external CDN (DevTools → Network shows `/api/scalar.js` served locally).

- [ ] **Step 8: Commit**

```bash
cd backend && git add Cargo.toml Cargo.lock src/lib.rs tests/api/api_test_client_api.rs
git commit -m "feat(api): replace RapiDoc with self-hosted Scalar reference"
```

---

## Self-Review

**Spec coverage:**
- Scalar (self-hosted, replace RapiDoc) → Task 6. ✅
- Public validation endpoint (status + dates, no subject) → Tasks 1–3. ✅
- `serial_hex` prerequisite (issuance + backfill) → Task 2 (gap the spec implied; without it validation is non-functional for non-ACME certs). ✅
- CA polish: format `pem|der`, filenames/MIME → Task 4; fullchain → Task 5. ✅
- No migration; reuse existing columns/index → honored (Global Constraints). ✅

**Placeholder scan:** No TBD/TODO. Two explicitly-flagged adapt-to-compiler spots (DownloadResponse derive if `Default` needed; Scalar crate exact signatures) carry concrete fallbacks, not vague hand-waving.

**Type consistency:** `CertStatus`, `CertStatusResponse`, `CertStatusRow`, `compute_cert_status(now_ms, created_on, valid_until, revoked_at)`, `get_cert_status_by_serial_hex(String)`, `DownloadResponse::new_typed`, `tls_ca_download`, `aki_of`, `find_issuing_ca` are used with consistent names/signatures across tasks. Serial hex format (`{b:02x}`, no separators) is identical in issuance, backfill, tests, and matches ACME.
