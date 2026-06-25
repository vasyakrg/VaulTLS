# Import External CAs and Certificates — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow importing an existing CA (with or without its private key) and importing pre-issued leaf certificates, auto-importing the issuing CA from the chain, while blocking issuance/CRL on key-less CAs.

**Architecture:** New `certs/import.rs` module parses PEM/DER/PKCS#12 and verifies chains via OpenSSL `X509Store`. Two new admin-only multipart endpoints in `api.rs`. A migration adds `is_imported`; key-less CAs are detected by `key.is_empty()`. Issuance/CRL/ACME paths gain a `has_private_key()` guard.

**Tech Stack:** Rust 2024, Rocket 0.5.1 (built-in `Form`/`TempFile` — no extra feature), rusqlite + SQLCipher, openssl 0.10, rcgen (CRL). Tests use `#[cfg(test)]` units with OpenSSL fixtures and `VaulTLSClient` integration harness (`--features test-mode`).

## Global Constraints

- Rust edition: `2024`; backend crate `version = "1.2.0"`.
- All new endpoints require `AuthenticatedPrivileged` (admin), like `create_ca` (`api.rs:357`).
- Multipart uses `rocket::form::Form` + `rocket::fs::TempFile` — already available; do NOT add a Rocket feature (the `forms` feature does not exist in 0.5; `FromFormField` is already used in `enums.rs:155`).
- Errors: return `ApiError` (`data/error.rs`); `anyhow::Error` and `openssl::error::ErrorStack` auto-convert via existing `From` impls.
- CA private key is stored as PKCS#8 DER in `ca_certificates.key`; leaf data stored in `user_certificates.data` (PKCS#12 DER or PEM, auto-detected in `Certificate::from_row`, `common.rs:29`).
- Run tests with: `cargo test --features test-mode` (from `backend/`).
- Commit after each task. Branch: `feat/import-external-certs`.

---

## File Structure

- Create: `backend/migrations/11-import/up.sql`, `backend/migrations/11-import/down.sql`
- Create: `backend/src/certs/import.rs` — parsing, chain verification, classification, issuing-CA detection
- Modify: `backend/src/certs/mod.rs` — register `pub mod import;`
- Modify: `backend/src/certs/common.rs` — `CA.is_imported` field + `CA::has_private_key()`
- Modify: `backend/src/db.rs` — `is_imported` column in CA SELECT/INSERT; NULL-key fix; `find_ca_by_ski`
- Modify: `backend/src/api.rs` — two import handlers, issuance/CRL guards
- Modify: `backend/src/lib.rs` — mount new routes in both `openapi_get_routes!` blocks (≈205, ≈275)
- Modify: `backend/src/acme/routes.rs` — guard in `finalize_order` (≈609)
- Test: unit tests inside `import.rs`; integration in `backend/tests/api/api_test_functionality.rs`

---

## Task 0: Data model — `is_imported` column, key-less CA support

**Files:**
- Create: `backend/migrations/11-import/up.sql`, `.../down.sql`
- Modify: `backend/src/certs/common.rs:64-77` (struct `CA`)
- Modify: `backend/src/db.rs` (`insert_ca` 165-177; `get_ca_by_query` 205-225; `get_all_ca` 228-246; SELECTs 190-201)

**Interfaces:**
- Produces: `CA { ..., pub is_imported: bool }`; `impl CA { pub fn has_private_key(&self) -> bool }`.
- Produces: `insert_ca` now persists `is_imported`; CA reads tolerate NULL `key`.

- [ ] **Step 1: Write the failing test** (append to `backend/src/db.rs`, inside a new `#[cfg(test)]` block at end of file)

```rust
#[cfg(test)]
mod import_tests {
    use super::*;
    use crate::certs::common::CA;
    use crate::data::enums::CAType;
    use crate::data::objects::Name;

    async fn mem_db() -> VaulTLSDB {
        // test-mode constructor opens an in-memory encrypted DB and runs migrations
        VaulTLSDB::new_in_memory().await.unwrap()
    }

    #[tokio::test]
    async fn keyless_ca_roundtrips_and_reports_no_private_key() {
        let db = mem_db().await;
        let ca = CA {
            id: -1,
            name: Name::from("Imported Root"),
            created_on: 0,
            valid_until: 1,
            ca_type: CAType::TLS,
            cert: vec![1, 2, 3],
            key: Vec::new(),          // key-less external CA
            crl_number: 0,
            is_imported: true,
        };
        let saved = db.insert_ca(ca).await.unwrap();
        let fetched = db.get_ca_by_id(saved.id).await.unwrap();
        assert!(fetched.is_imported);
        assert!(!fetched.has_private_key());
        assert!(fetched.key.is_empty());
    }
}
```

> If `VaulTLSDB::new_in_memory` does not exist, add a `#[cfg(any(test, feature = "test-mode"))]` constructor mirroring the existing pool setup but with `":memory:"`, running the same migrations. Check the top of `db.rs` for the current constructor and replicate its migration call.

- [ ] **Step 2: Run test, verify it fails to compile** (no `is_imported`, no `has_private_key`)

Run: `cargo test --features test-mode db::import_tests -- --nocapture`
Expected: compile error `no field 'is_imported' on type CA`.

- [ ] **Step 3: Add the migration**

`backend/migrations/11-import/up.sql`:
```sql
ALTER TABLE ca_certificates ADD COLUMN is_imported INTEGER NOT NULL DEFAULT 0;
```
`backend/migrations/11-import/down.sql`:
```sql
ALTER TABLE ca_certificates DROP COLUMN is_imported;
```

- [ ] **Step 4: Extend struct `CA`** (`common.rs:64-77`) — add field and method

```rust
#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct CA {
    pub id: i64,
    pub name: Name,
    pub created_on: i64,
    pub valid_until: i64,
    pub ca_type: CAType,
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(skip)]
    pub key: Vec<u8>,
    #[serde(skip)]
    pub crl_number: i64,
    pub is_imported: bool,
}

impl CA {
    /// True if this CA holds a usable private key (i.e. can issue/revoke).
    pub fn has_private_key(&self) -> bool {
        !self.key.is_empty()
    }
}
```

> Fix all `CA { .. }` literals that now miss `is_imported`. Known sites: `tls_cert.rs:190` (`build_ca` → add `is_imported: false`), and `ssh_cert.rs` `build_ca` (search for `Ok(CA{` / `CA {`). Internally generated CAs use `is_imported: false`.

- [ ] **Step 5: Update `db.rs` CA persistence** — INSERT, all SELECTs, NULL-key tolerance

`insert_ca` (165-177):
```rust
conn.execute(
    "INSERT INTO ca_certificates (name, created_on, valid_until, type, certificate, key, crl_number, is_imported) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    params![ca.name, ca.created_on, ca.valid_until, ca.ca_type as u8, ca.cert, ca.key, ca.crl_number, ca.is_imported as i64],
)?;
```
Add `, is_imported` to the column list in the three SELECT strings (`get_latest_tls_ca` 190, `get_latest_ssh_ca` 195, `get_ca_by_id` 200, `get_all_ca` 230). In `get_ca_by_query` (214-223) and `get_all_ca` (233-242) build the struct with NULL-key tolerance and the new column:
```rust
Ok(CA {
    id: row.get(0)?,
    name: row.get(1).unwrap_or_default(),
    created_on: row.get(2)?,
    valid_until: row.get(3)?,
    ca_type: row.get(4)?,
    cert: row.get(5).unwrap_or_default(),
    key: row.get(6).unwrap_or_default(),   // NULL key -> empty Vec, no panic
    crl_number: row.get(7)?,
    is_imported: row.get::<_, i64>(8)? != 0,
})
```

- [ ] **Step 6: Run test, verify it passes**

Run: `cargo test --features test-mode db::import_tests -- --nocapture`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/migrations/11-import backend/src/certs/common.rs backend/src/db.rs backend/src/certs/tls_cert.rs backend/src/certs/ssh_cert.rs
git commit -m "feat(import): add is_imported column and key-less CA support"
```

---

## Task 1: Crypto parsing — `certs/import.rs` (PEM/DER/PKCS#12)

**Files:**
- Create: `backend/src/certs/import.rs`
- Modify: `backend/src/certs/mod.rs` (add `pub mod import;`)

**Interfaces:**
- Produces:
  - `parse_cert(bytes: &[u8]) -> anyhow::Result<X509>` (PEM, fallback DER)
  - `parse_private_key(bytes: &[u8]) -> anyhow::Result<PKey<Private>>` (PEM, fallback DER/PKCS#8)
  - `parse_pkcs12(bytes: &[u8], password: &str) -> anyhow::Result<(X509, Option<PKey<Private>>, Vec<X509>)>` returns `(leaf, key, chain)`
  - `parse_pem_bundle(bytes: &[u8]) -> anyhow::Result<Vec<X509>>`

- [ ] **Step 1: Register module** in `backend/src/certs/mod.rs`

```rust
pub mod import;
```

- [ ] **Step 2: Write failing tests** — create `backend/src/certs/import.rs` with tests first

```rust
use anyhow::{anyhow, Result};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

// ---- implementations added in Step 4 ----

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::hash::MessageDigest;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use openssl::x509::extension::BasicConstraints;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;

    fn keypair() -> PKey<Private> {
        let g = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&g).unwrap()).unwrap()
    }

    /// Build a self-signed CA cert with given CN. Returns (cert, key).
    fn self_signed_ca(cn: &str) -> (X509, PKey<Private>) {
        let key = keypair();
        let mut nb = X509NameBuilder::new().unwrap();
        nb.append_entry_by_text("CN", cn).unwrap();
        let name = nb.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    #[test]
    fn parse_cert_accepts_pem_and_der() {
        let (cert, _) = self_signed_ca("Root");
        let pem = cert.to_pem().unwrap();
        let der = cert.to_der().unwrap();
        assert!(parse_cert(&pem).is_ok());
        assert!(parse_cert(&der).is_ok());
    }

    #[test]
    fn parse_private_key_accepts_pem_and_der() {
        let key = keypair();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        let der = key.private_key_to_der().unwrap();
        assert!(parse_private_key(&pem).is_ok());
        assert!(parse_private_key(&der).is_ok());
    }

    #[test]
    fn parse_pem_bundle_splits_multiple_blocks() {
        let (a, _) = self_signed_ca("A");
        let (b, _) = self_signed_ca("B");
        let mut bundle = a.to_pem().unwrap();
        bundle.extend_from_slice(&b.to_pem().unwrap());
        let parsed = parse_pem_bundle(&bundle).unwrap();
        assert_eq!(parsed.len(), 2);
    }
}
```

- [ ] **Step 3: Run tests, verify they fail to compile** (functions undefined)

Run: `cargo test --features test-mode certs::import -- --nocapture`
Expected: compile error `cannot find function parse_cert`.

- [ ] **Step 4: Implement parsers** (insert above the `#[cfg(test)]` block)

```rust
/// Parse an X.509 certificate, trying PEM first then DER.
pub fn parse_cert(bytes: &[u8]) -> Result<X509> {
    X509::from_pem(bytes).or_else(|_| X509::from_der(bytes))
        .map_err(|e| anyhow!("not a valid PEM/DER certificate: {e}"))
}

/// Parse a private key, trying PEM (PKCS#8/SEC1) then DER (PKCS#8).
pub fn parse_private_key(bytes: &[u8]) -> Result<PKey<Private>> {
    PKey::private_key_from_pem(bytes)
        .or_else(|_| PKey::private_key_from_der(bytes))
        .map_err(|e| anyhow!("not a valid PEM/DER private key: {e}"))
}

/// Parse a PKCS#12 blob into (leaf cert, optional key, chain certs).
pub fn parse_pkcs12(bytes: &[u8], password: &str) -> Result<(X509, Option<PKey<Private>>, Vec<X509>)> {
    let parsed = Pkcs12::from_der(bytes)?.parse2(password)?;
    let leaf = parsed.cert.ok_or_else(|| anyhow!("PKCS#12 has no certificate"))?;
    let chain = match parsed.ca {
        Some(stack) => stack.into_iter().collect(),
        None => Vec::new(),
    };
    Ok((leaf, parsed.pkey, chain))
}

/// Split a PEM bundle into individual certificates.
pub fn parse_pem_bundle(bytes: &[u8]) -> Result<Vec<X509>> {
    let certs = X509::stack_from_pem(bytes)?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates in PEM bundle"));
    }
    Ok(certs)
}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `cargo test --features test-mode certs::import -- --nocapture`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add backend/src/certs/import.rs backend/src/certs/mod.rs
git commit -m "feat(import): add PEM/DER/PKCS12 parsers in certs::import"
```

---

## Task 2: Chain verification, classification, issuing-CA detection

**Files:**
- Modify: `backend/src/certs/import.rs`

**Interfaces:**
- Produces:
  - `fn is_ca_cert(cert: &X509) -> bool` (self-signed or CA basic-constraint heuristic via SKI==issuer match is not enough; use `X509::not_after`? No — use the helper below)
  - `fn find_issuing_ca(leaf: &X509, chain: &[X509]) -> Option<X509>` — match `chain[i].subject_key_id()` to `leaf.authority_key_id()`, fallback to issuer/subject DN equality
  - `fn verify_signed_by(leaf: &X509, issuer: &X509) -> bool` — `X509Store` single-step verification

- [ ] **Step 1: Write failing tests** (extend the `#[cfg(test)] mod tests`)

```rust
    use openssl::x509::extension::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

    /// Issue a leaf signed by `ca`, copying AKI from the CA.
    fn leaf_signed_by(cn: &str, ca: &X509, ca_key: &PKey<Private>) -> (X509, PKey<Private>) {
        let key = keypair();
        let mut nb = X509NameBuilder::new().unwrap();
        nb.append_entry_by_text("CN", cn).unwrap();
        let name = nb.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(ca.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(90).unwrap()).unwrap();
        let ski = SubjectKeyIdentifier::new().build(&b.x509v3_context(Some(ca), None)).unwrap();
        b.append_extension(ski).unwrap();
        let aki = AuthorityKeyIdentifier::new().keyid(true).build(&b.x509v3_context(Some(ca), None)).unwrap();
        b.append_extension(aki).unwrap();
        b.sign(ca_key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    #[test]
    fn verify_signed_by_accepts_correct_issuer_and_rejects_wrong() {
        let (ca, ca_key) = self_signed_ca("Real CA");
        let (other, _) = self_signed_ca("Other CA");
        let (leaf, _) = leaf_signed_by("leaf.example.com", &ca, &ca_key);
        assert!(verify_signed_by(&leaf, &ca));
        assert!(!verify_signed_by(&leaf, &other));
    }

    #[test]
    fn find_issuing_ca_locates_signer_in_chain() {
        let (ca, ca_key) = self_signed_ca("Issuing CA");
        let (leaf, _) = leaf_signed_by("leaf", &ca, &ca_key);
        let found = find_issuing_ca(&leaf, &[ca.clone()]).expect("issuer found");
        assert_eq!(found.subject_name().try_cmp(ca.subject_name()).unwrap(), std::cmp::Ordering::Equal);
    }
```

- [ ] **Step 2: Run, verify fail** — `cargo test --features test-mode certs::import` → compile error (undefined fns).

- [ ] **Step 3: Implement** (add to `import.rs`, above tests)

```rust
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509StoreContext;

/// Verify `leaf` is directly signed by `issuer` using a one-entry trust store.
pub fn verify_signed_by(leaf: &X509, issuer: &X509) -> bool {
    let Ok(mut builder) = X509StoreBuilder::new() else { return false };
    if builder.add_cert(issuer.clone()).is_err() { return false }
    let store = builder.build();
    let Ok(empty) = Stack::new() else { return false };
    let Ok(mut ctx) = X509StoreContext::new() else { return false };
    ctx.init(&store, leaf, &empty, |c| c.verify_cert()).unwrap_or(false)
}

/// Find the cert in `chain` that issued `leaf`: match AKI->SKI, fallback to DN.
pub fn find_issuing_ca(leaf: &X509, chain: &[X509]) -> Option<X509> {
    if let Some(aki) = leaf.authority_key_id() {
        for c in chain {
            if let Some(ski) = c.subject_key_id() {
                if ski.as_slice() == aki.as_slice() {
                    return Some(c.clone());
                }
            }
        }
    }
    // Fallback: issuer DN == candidate subject DN
    for c in chain {
        if leaf.issuer_name().try_cmp(c.subject_name()).map(|o| o.is_eq()).unwrap_or(false) {
            return Some(c.clone());
        }
    }
    None
}
```

- [ ] **Step 4: Run, verify pass** — `cargo test --features test-mode certs::import` → 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/certs/import.rs
git commit -m "feat(import): chain verification and issuing-CA detection"
```

---

## Task 3: Auto-import CA — find-or-create external CA by SKI

**Files:**
- Modify: `backend/src/db.rs` (add `find_ca_by_ski`-style lookup using existing `get_all_ca`)
- Modify: `backend/src/certs/import.rs` (add `ski_of`)

**Interfaces:**
- Produces: `fn ski_of(cert: &X509) -> Option<Vec<u8>>` in `import.rs`.
- Produces: `db.find_imported_ca_by_cert(cert_der: &[u8]) -> Result<Option<CA>>` — returns existing imported CA whose stored cert has the same SKI.

- [ ] **Step 1: Write failing test** (`db.rs` `import_tests`)

```rust
    #[tokio::test]
    async fn find_imported_ca_dedupes_by_ski() {
        use crate::certs::import::ski_of;
        use openssl::x509::X509;
        let db = mem_db().await;
        // Build a self-signed CA cert (reuse helper pattern inline)
        let cert_der = super::tests_support::self_signed_ca_der("Dedup CA");
        let x = X509::from_der(&cert_der).unwrap();
        assert!(ski_of(&x).is_some());

        let ca = CA { id: -1, name: Name::from("Dedup CA"), created_on: 0, valid_until: 1,
            ca_type: CAType::TLS, cert: cert_der.clone(), key: Vec::new(), crl_number: 0, is_imported: true };
        let saved = db.insert_ca(ca).await.unwrap();

        let found = db.find_imported_ca_by_cert(&cert_der).await.unwrap();
        assert_eq!(found.map(|c| c.id), Some(saved.id));
    }
```

> Add a tiny `tests_support` helper module exposing `self_signed_ca_der` (reuse the `self_signed_ca` body from `import.rs` tests, returning DER) so both test modules can build fixtures. Place it under `#[cfg(test)] pub(crate) mod tests_support` in `certs/import.rs`.

- [ ] **Step 2: Run, verify fail** — undefined `ski_of` / `find_imported_ca_by_cert`.

- [ ] **Step 3: Implement `ski_of`** (`import.rs`)

```rust
/// Subject Key Identifier bytes, if present.
pub fn ski_of(cert: &X509) -> Option<Vec<u8>> {
    cert.subject_key_id().map(|s| s.as_slice().to_vec())
}
```

- [ ] **Step 4: Implement `find_imported_ca_by_cert`** (`db.rs`)

```rust
/// Find an already-imported CA whose stored cert shares the SKI of `cert_der`.
pub(crate) async fn find_imported_ca_by_cert(&self, cert_der: &[u8]) -> Result<Option<CA>> {
    use crate::certs::import::ski_of;
    use openssl::x509::X509;
    let target = X509::from_der(cert_der).ok().and_then(|c| ski_of(&c));
    let Some(target_ski) = target else { return Ok(None) };
    for ca in self.get_all_ca().await? {
        if !ca.is_imported { continue }
        if let Ok(x) = X509::from_der(&ca.cert) {
            if ski_of(&x).as_deref() == Some(target_ski.as_slice()) {
                return Ok(Some(ca));
            }
        }
    }
    Ok(None)
}
```

- [ ] **Step 5: Run, verify pass** — `cargo test --features test-mode db::import_tests` → PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/db.rs backend/src/certs/import.rs
git commit -m "feat(import): dedupe imported CA by SKI (find-or-create helper)"
```

---

## Task 4: Endpoint `POST /certificates/ca/import`

**Files:**
- Modify: `backend/src/api.rs` (new handler + form struct)
- Modify: `backend/src/lib.rs` (mount in both route blocks)
- Test: `backend/tests/api/api_test_functionality.rs`

**Interfaces:**
- Consumes: `parse_cert`, `parse_private_key` (Task 1), `CA::has_private_key`, `db.insert_ca`, `save_ca`.
- Produces: route `import_ca` returning `Json<i64>` (new CA id).

- [ ] **Step 1: Write failing integration test** (add to `api_test_functionality.rs`; follow existing `VaulTLSClient` style)

```rust
#[tokio::test]
async fn import_external_ca_with_key_succeeds() {
    use rocket::http::ContentType;
    let client = VaulTLSClient::new_authenticated().await;

    // Build a CA cert+key with openssl in the test
    let (ca_pem, key_pem) = crate::common::helper::self_signed_ca_pem("Imported CA");

    let boundary = "X-BOUNDARY";
    let body = crate::common::helper::multipart_two_files(
        boundary, "ca_cert", "ca.pem", &ca_pem, "ca_key", "ca.key", &key_pem,
    );
    let response = client
        .post("/certificates/ca/import")
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch().await;
    assert_eq!(response.status(), rocket::http::Status::Ok);
}
```

> Add helpers in `backend/tests/common/helper.rs`: `self_signed_ca_pem(cn) -> (Vec<u8>, Vec<u8>)` (cert PEM, key PEM) and `multipart_two_files(boundary, f1, n1, d1, f2, n2, d2) -> Vec<u8>` building a valid multipart body. Use `openssl` crate (already a backend dep; add to `[dev-dependencies]` of the test crate if the integration crate cannot see it — it can, tests live in `backend/`).

- [ ] **Step 2: Run, verify fail** — 404 (route not mounted).

Run: `cargo test --features test-mode import_external_ca_with_key_succeeds`
Expected: assertion fails `404 != 200`.

- [ ] **Step 3: Add form + handler** (`api.rs`, near `create_ca` ~354)

```rust
use rocket::form::Form;
use rocket::fs::TempFile;
use rocket::data::ToByteUnit;

#[derive(FromForm)]
pub struct ImportCaForm<'r> {
    pub ca_cert: TempFile<'r>,
    pub ca_key: Option<TempFile<'r>>,
    pub name: Option<String>,
}

async fn read_tempfile(file: &TempFile<'_>) -> Result<Vec<u8>, ApiError> {
    use rocket::tokio::io::AsyncReadExt;
    let mut stream = file.open().await.map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(buf)
}

#[openapi(tag = "Certificates")]
#[post("/certificates/ca/import", data = "<form>")]
/// Import an existing CA (optionally with its private key). Requires admin role.
pub(crate) async fn import_ca(
    state: &State<AppState>,
    form: Form<ImportCaForm<'_>>,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<i64>, ApiError> {
    use crate::certs::import::{parse_cert, parse_private_key};
    let cert_bytes = read_tempfile(&form.ca_cert).await?;
    let cert = parse_cert(&cert_bytes).map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let key_der = match &form.ca_key {
        Some(f) => {
            let kb = read_tempfile(f).await?;
            let key = parse_private_key(&kb).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            key.private_key_to_der().map_err(ApiError::from)?
        }
        None => Vec::new(),
    };

    let cn = form.name.clone().unwrap_or_else(|| cn_from_cert(&cert));
    let not_after_ms = asn1_to_unix_ms(cert.not_after());
    let mut ca = CA {
        id: -1,
        name: Name::from(cn),
        created_on: 0,
        valid_until: not_after_ms,
        ca_type: CAType::TLS,
        cert: cert.to_der().map_err(ApiError::from)?,
        key: key_der,
        crl_number: 0,
        is_imported: true,
    };
    ca = state.db.insert_ca(ca).await?;
    save_ca(&ca)?;
    Ok(Json(ca.id))
}
```

Add two small helpers in `api.rs` (or `certs/import.rs` and re-export):
```rust
fn cn_from_cert(cert: &openssl::x509::X509) -> String {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
        .unwrap_or_else(|| "Imported CA".to_string())
}

fn asn1_to_unix_ms(t: &openssl::asn1::Asn1TimeRef) -> i64 {
    // Asn1Time diff from epoch -> seconds -> ms
    let epoch = openssl::asn1::Asn1Time::from_unix(0).unwrap();
    let diff = epoch.diff(t).unwrap();
    ((diff.days as i64) * 86_400 + diff.secs as i64) * 1000
}
```

- [ ] **Step 4: Mount route** in `lib.rs` — add `import_ca,` to BOTH `openapi_get_routes![...]` blocks (after `create_ca`, lines ~174 and ~265).

- [ ] **Step 5: Run, verify pass**

Run: `cargo test --features test-mode import_external_ca_with_key_succeeds`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/api.rs backend/src/lib.rs backend/tests
git commit -m "feat(import): POST /certificates/ca/import endpoint"
```

---

## Task 5: Endpoint `POST /certificates/import` (leaf + auto-import CA)

**Files:**
- Modify: `backend/src/api.rs` (handler + form)
- Modify: `backend/src/lib.rs` (mount)
- Test: `backend/tests/api/api_test_functionality.rs`

**Interfaces:**
- Consumes: `parse_cert`, `parse_private_key`, `parse_pkcs12`, `parse_pem_bundle`, `find_issuing_ca`, `verify_signed_by`, `db.find_imported_ca_by_cert`, `db.insert_ca`, `db.insert_user_cert`.
- Produces: route `import_certificate` returning `Json<Certificate>`.

- [ ] **Step 1: Write failing test** — case B (leaf+key+chain, no CA key), CA auto-imported

```rust
#[tokio::test]
async fn import_leaf_auto_imports_ca_case_b() {
    use rocket::http::{ContentType, Status};
    let client = VaulTLSClient::new_authenticated().await;

    // CA (we keep only its cert in the chain — no CA key uploaded)
    let (ca_pem, ca_key_pem) = crate::common::helper::self_signed_ca_pem("Public-ish CA");
    let (leaf_pem, leaf_key_pem) = crate::common::helper::leaf_signed_by_pem("svc.example.com", &ca_pem, &ca_key_pem);

    let boundary = "B2";
    // fields: cert, key, chain, user_id  (no ca_id -> auto)
    let body = crate::common::helper::multipart_import_leaf(
        boundary, &leaf_pem, &leaf_key_pem, &ca_pem, 1,
    );
    let response = client
        .post("/certificates/import")
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // The CA list now contains an imported, key-less CA
    let cas = client.get_all_ca().await.unwrap();
    assert!(cas.iter().any(|c| c.is_imported));
}
```

> Add `leaf_signed_by_pem(cn, ca_pem, ca_key_pem) -> (Vec<u8>, Vec<u8>)` and `multipart_import_leaf(...)` to `tests/common/helper.rs`. If `get_all_ca` helper does not exist on `VaulTLSClient`, add a thin GET wrapper to `test_client.rs` deserializing `Vec<CA>`.

- [ ] **Step 2: Run, verify fail** — 404.

- [ ] **Step 3: Implement form + handler** (`api.rs`)

```rust
#[derive(FromForm)]
pub struct ImportCertForm<'r> {
    pub p12: Option<TempFile<'r>>,
    pub password: Option<String>,
    pub cert: Option<TempFile<'r>>,
    pub key: Option<TempFile<'r>>,
    pub chain: Option<TempFile<'r>>,
    pub user_id: i64,
    pub ca_id: Option<i64>,
    pub cert_type: Option<CertificateType>,
    pub renew_method: Option<CertificateRenewMethod>,
}

#[openapi(tag = "Certificates")]
#[post("/certificates/import", data = "<form>")]
/// Import a pre-issued leaf certificate; auto-imports its CA from the chain. Requires admin role.
pub(crate) async fn import_certificate(
    state: &State<AppState>,
    form: Form<ImportCertForm<'_>>,
    _authentication: AuthenticatedPrivileged,
) -> Result<Json<Certificate>, ApiError> {
    use crate::certs::import::{parse_cert, parse_private_key, parse_pkcs12, parse_pem_bundle, find_issuing_ca, verify_signed_by};
    use openssl::x509::X509;

    // 1) Obtain leaf, key, chain and the raw bytes we will store.
    let (leaf, _key, chain, stored): (X509, Option<_>, Vec<X509>, CertData) =
        if let Some(p12) = &form.p12 {
            let bytes = read_tempfile(p12).await?;
            let pwd = form.password.clone().unwrap_or_default();
            let (leaf, key, chain) = parse_pkcs12(&bytes, &pwd).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            (leaf, key, chain, CertData::Pkcs12(bytes))
        } else {
            let cert_f = form.cert.as_ref().ok_or_else(|| ApiError::BadRequest("cert or p12 required".into()))?;
            let key_f = form.key.as_ref().ok_or_else(|| ApiError::BadRequest("key required with cert".into()))?;
            let cert_bytes = read_tempfile(cert_f).await?;
            let key_bytes = read_tempfile(key_f).await?;
            let leaf = parse_cert(&cert_bytes).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            let key = parse_private_key(&key_bytes).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            let chain = match &form.chain {
                Some(cf) => parse_pem_bundle(&read_tempfile(cf).await?).map_err(|e| ApiError::BadRequest(e.to_string()))?,
                None => Vec::new(),
            };
            // Repackage as PKCS#12 for uniform storage (mirrors build_common)
            let pwd = form.password.clone().unwrap_or_default();
            let mut ca_stack = openssl::stack::Stack::new()?;
            for c in &chain { ca_stack.push(c.clone())?; }
            let p12 = openssl::pkcs12::Pkcs12::builder()
                .name("imported").ca(ca_stack).cert(&leaf).pkey(&key).build2(&pwd)?;
            (leaf, Some(key), chain, CertData::Pkcs12(p12.to_der()?))
        };

    // 2) Resolve CA: explicit ca_id, else auto from chain.
    let ca_id = match form.ca_id {
        Some(id) => id,
        None => {
            let issuer = find_issuing_ca(&leaf, &chain)
                .ok_or_else(|| ApiError::BadRequest("could not find issuing CA in chain".into()))?;
            if !verify_signed_by(&leaf, &issuer) {
                return Err(ApiError::BadRequest("leaf is not signed by the provided CA chain".into()));
            }
            let issuer_der = issuer.to_der()?;
            match state.db.find_imported_ca_by_cert(&issuer_der).await? {
                Some(existing) => existing.id,
                None => {
                    let cn = cn_from_cert(&issuer);
                    let ca = CA { id: -1, name: Name::from(cn), created_on: 0,
                        valid_until: asn1_to_unix_ms(issuer.not_after()), ca_type: CAType::TLS,
                        cert: issuer_der, key: Vec::new(), crl_number: 0, is_imported: true };
                    state.db.insert_ca(ca).await?.id
                }
            }
        }
    };

    // 3) Persist the leaf certificate.
    let cert_type = form.cert_type.unwrap_or(CertificateType::TLSServer);
    let cert = Certificate {
        id: -1,
        name: Name::from(cn_from_cert(&leaf)),
        created_on: 0,
        valid_until: asn1_to_unix_ms(leaf.not_after()),
        certificate_type: cert_type,
        user_id: form.user_id,
        renew_method: form.renew_method.unwrap_or(CertificateRenewMethod::None),
        ca_id,
        revoked_at: None,
        data: stored,
        password: form.password.clone().unwrap_or_default(),
    };
    let saved = state.db.insert_user_cert(cert).await?;
    Ok(Json(saved))
}
```

- [ ] **Step 4: Mount** `import_certificate,` in both route blocks (`lib.rs`).

- [ ] **Step 5: Run, verify pass**

Run: `cargo test --features test-mode import_leaf_auto_imports_ca_case_b`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/api.rs backend/src/lib.rs backend/tests
git commit -m "feat(import): POST /certificates/import with CA auto-import"
```

---

## Task 6: Guards — block issuance/CRL on key-less CAs

**Files:**
- Modify: `backend/src/api.rs` (`get_appropriate_ca` ~435 or `build_certificate` ~461; `revoke_certificate` ~701; `download_crl` ~730)
- Modify: `backend/src/acme/routes.rs` (`finalize_order` ~609)
- Test: `backend/tests/api/api_test_functionality.rs`

**Interfaces:**
- Consumes: `CA::has_private_key()`.

- [ ] **Step 1: Write failing test** — issuing from a key-less imported CA must 400

```rust
#[tokio::test]
async fn issuing_from_keyless_ca_is_rejected() {
    use rocket::http::{ContentType, Status};
    let client = VaulTLSClient::new_authenticated().await;

    // Import a CA WITHOUT a key
    let (ca_pem, _ca_key_pem) = crate::common::helper::self_signed_ca_pem("Keyless CA");
    let boundary = "B3";
    let body = crate::common::helper::multipart_one_file(boundary, "ca_cert", "ca.pem", &ca_pem);
    let resp = client.post("/certificates/ca/import")
        .header(ContentType::new("multipart","form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let ca_id: i64 = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();

    // Attempt to issue a normal cert against it
    let req = vaultls::data::api::CreateUserCertificateRequest {
        cert_name: "x".into(), validity_duration: Some(1), validity_unit: Some(vaultls::data::enums::TimespanUnit::Year),
        user_id: 1, notify_user: None, system_generated_password: false, cert_password: Some("pw".into()),
        cert_type: Some(vaultls::data::enums::CertificateType::TLSClient), usage_limit: None,
        renew_method: None, ca_id: Some(ca_id),
    };
    let resp = client.post("/certificates").header(ContentType::JSON)
        .body(serde_json::to_string(&req).unwrap()).dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest);
}
```

- [ ] **Step 2: Run, verify fail** — currently 500 (OpenSSL error on empty key) or 200, not 400.

- [ ] **Step 3: Add guard in issuance path** — in `get_appropriate_ca` (`api.rs:435-447`), after resolving the CA:

```rust
async fn get_appropriate_ca(state: &State<AppState>, payload: &CreateUserCertificateRequest) -> Result<CA, ApiError> {
    let ca_result = match payload.ca_id {
        Some(ca_id) => state.db.get_ca_by_id(ca_id).await,
        None => match payload.cert_type {
            Some(CertificateType::SSHClient) | Some(CertificateType::SSHServer) => state.db.get_latest_ssh_ca().await,
            _ => state.db.get_latest_tls_ca().await
        }
    };
    let ca = ca_result.map_err(|_| ApiError::BadRequest(format!("The CA id {:?} does not exist", payload.ca_id)))?;
    if !ca.has_private_key() {
        return Err(ApiError::BadRequest("This CA was imported without a private key and cannot issue certificates".into()));
    }
    Ok(ca)
}
```

- [ ] **Step 4: Add guard in `revoke_certificate`** (`api.rs:710`, after loading `ca`) and `download_crl` (`api.rs:735`, after loading `ca`):

```rust
    if !ca.has_private_key() {
        return Err(ApiError::BadRequest("This CA has no private key; cannot generate CRL/KRL".into()));
    }
```

- [ ] **Step 5: Add guard in ACME `finalize_order`** (`acme/routes.rs` ~609, before `issue_cert_from_csr`):

```rust
    if !ca.has_private_key() {
        return Err(/* existing AcmeError path */ AcmeError::server_internal("CA has no private key"));
    }
```

> Match the local error type/return used in `finalize_order`; if it returns a different error enum, use that crate's "server internal"/"bad request" equivalent. Read 20 lines around the call site first.

- [ ] **Step 6: Run, verify pass** — `cargo test --features test-mode issuing_from_keyless_ca_is_rejected` → PASS.

- [ ] **Step 7: Run the full suite** — `cargo test --features test-mode` → all green (no regressions).

- [ ] **Step 8: Commit**

```bash
git add backend/src/api.rs backend/src/acme/routes.rs backend/tests
git commit -m "feat(import): guard issuance/CRL/ACME against key-less CAs"
```

---

## Task 7: OpenAPI/docs sanity + final verification

**Files:**
- Modify: `backend/src/lib.rs` (confirm both blocks mount `import_ca`, `import_certificate`)

- [ ] **Step 1: Build release image-equivalent compile**

Run: `cargo build --release --locked` (from `backend/`)
Expected: success.

- [ ] **Step 2: Full test run**

Run: `cargo test --features test-mode`
Expected: all tests pass, including new import tests.

- [ ] **Step 3: Manual E2E (optional, documented in spec)** — run binary, `curl` case A and B per `docs/specs/import-external-certs.md`.

- [ ] **Step 4: Commit any doc tweaks & open PR**

```bash
git add -A
git commit -m "docs(import): finalize import feature" || true
git push origin feat/import-external-certs
```

---

## Self-Review Notes

- **Spec coverage:** migration+is_imported (T0) · parsers (T1) · verify/classify (T2) · auto-import dedup (T3) · CA endpoint (T4) · leaf endpoint + auto-CA (T5) · 7 guard points (T6: issuance via `get_appropriate_ca`, SSH shares that path, revoke, download_crl, ACME finalize) · mount+build (T7). All spec sections mapped.
- **SSH import:** spec marks it secondary; this plan covers TLS end-to-end. SSH-CA import is a follow-up (reuse `import_ca` with `ca_type=ssh`, parse via `ssh_key::PrivateKey`), not blocking.
- **Assumptions to verify during execution:** `VaulTLSDB::new_in_memory` may need adding; `Asn1TimeRef::diff` signature; ACME finalize error type. Each is flagged inline.
