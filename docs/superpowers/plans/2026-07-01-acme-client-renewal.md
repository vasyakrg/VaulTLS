# ACME-client certbot-like Renewal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ACME-client (Let's Encrypt) certificate renewal behave like certbot: reuse a still-valid LE authorization (no redundant TXT), renew the certificate in place (same row/ID), and auto-renew on a schedule (semi-auto: unattended when the authz is valid, otherwise create a pending order + notify).

**Architecture:** (A) `create_order` only emits TXT for `Pending` authorizations; (B) a nullable `renews_cert_id` on `acme_client_orders` drives an in-place `UPDATE` of `user_certificates` on issue instead of an `INSERT`; (C) the expiry ticker routes ACME certs to a new renewal path (30-day window, dedup guard, no `renew_method` reset) and — importantly — stops routing them through the internal-CA renewal path; (D) the UI renew button passes `renews_cert_id` so manual renew is also in-place.

**Tech Stack:** Rust (Rocket, rocket-okapi, instant-acme 0.8, hickory-resolver, rusqlite + rusqlite_migration via include_dir), Vue 3 + TS + Pinia + PrimeVue.

## Global Constraints

- Renewal key: a NEW key each renewal (instant-acme `finalize()` generates it). No key reuse.
- Renewal window: 30 days before expiry (`now + 1000*60*60*24*30`). Fixed, not configurable.
- Auto-renew is opt-in via `renew_method ∈ {Renew(2), RenewAndNotify(3)}`; `Notify(1)` keeps its old "email reminder once" behavior; `None(0)` does nothing.
- ACME certs (`acme_provider_id.is_some()`) MUST NOT go through the internal-CA renewal path (`handle_expiry` Renew/RenewAndNotify branch).
- For ACME auto-renew, `renew_method` MUST NOT be reset to `None` (it must keep renewing); the reset stays only for the internal-CA and ACME-Notify paths.
- Backend compiles clean, ZERO warnings (`cargo build` from `backend/`). Frontend type-check clean (`npx vue-tsc --noEmit` from `frontend/` → `ok`).
- Migration is additive (nullable column); existing orders get `renews_cert_id = NULL` and behave as before (INSERT).
- Work on branch `feat/acme-client-renewal` (already checked out). Local commits only; do NOT push.
- instant-acme facts: `AuthorizationHandle` derefs to `AuthorizationState` which has `pub status: AuthorizationStatus` (variants `Pending, Valid, Invalid, Revoked, Expired, Deactivated`) and `pub challenges: Vec<Challenge>`. `authz.challenge(ChallengeType::Dns01)` borrows `&mut self`.

---

### Task 1: Reuse valid authorization in create_order + guard set_ready

**Files:**
- Modify: `backend/src/acme_client/client.rs`

**Interfaces:**
- Produces: `fn authz_needs_dns_challenge(status: AuthorizationStatus) -> bool` — `true` only for `Pending`. Used by both `create_order` (whether to emit a TXT record) and `issue_order` (whether to call `set_ready`).

- [ ] **Step 1: Write the failing test**

Add inside the existing `#[cfg(test)] mod tests` block in `backend/src/acme_client/client.rs`:

```rust
    #[test]
    fn only_pending_authz_needs_dns_challenge() {
        use instant_acme::AuthorizationStatus::*;
        assert!(authz_needs_dns_challenge(Pending));
        assert!(!authz_needs_dns_challenge(Valid));
        assert!(!authz_needs_dns_challenge(Invalid));
        assert!(!authz_needs_dns_challenge(Deactivated));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && cargo test --lib only_pending_authz_needs_dns_challenge 2>&1 | tail -12`
Expected: FAIL — `cannot find function authz_needs_dns_challenge`.

- [ ] **Step 3: Add the helper + import**

In `backend/src/acme_client/client.rs`, extend the `use instant_acme::{...}` block to include `AuthorizationStatus`. Add the helper just above `create_order`:

```rust
/// True only when an authorization still requires the dns-01 challenge to be completed.
/// A `Valid` authorization (reused by the CA within its ~30-day window) needs no TXT record
/// and no `set_ready` call.
fn authz_needs_dns_challenge(status: AuthorizationStatus) -> bool {
    matches!(status, AuthorizationStatus::Pending)
}
```

- [ ] **Step 4: Apply in `create_order`**

Replace the `create_order` authorization loop body (the `while let Some(result) = authorizations.next().await { ... }` block that pushes to `txt_records`) with:

```rust
    let mut txt_records = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| anyhow!("failed to fetch authorization: {e}"))?;
        // Skip authorizations the CA already considers valid — no challenge/TXT needed (LE reuses
        // a valid authorization for ~30 days). Renewals within that window need no DNS step.
        if !authz_needs_dns_challenge(authz.status) {
            continue;
        }
        let challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("dns-01 challenge not offered for this authorization"))?;
        let value = challenge.key_authorization().dns_value();
        txt_records.push(TxtRecord {
            name: format!("_acme-challenge.{base_domain}"),
            value,
        });
    }
```

- [ ] **Step 5: Apply in `issue_order` set_ready loop**

Replace the set_ready loop (inside the `{ let mut authorizations = order.authorizations(); ... }` block at step "3. set_ready") with:

```rust
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz =
                result.map_err(|e| anyhow!("failed to fetch authorization: {e}"))?;
            // Only signal readiness for authorizations that are still pending; a valid
            // authorization has no outstanding challenge and set_ready would error.
            if !authz_needs_dns_challenge(authz.status) {
                continue;
            }
            if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
                challenge
                    .set_ready()
                    .await
                    .map_err(|e| anyhow!("set_ready failed: {e}"))?;
            }
        }
```

- [ ] **Step 6: Run test + build**

Run: `cd backend && cargo test --lib only_pending_authz_needs_dns_challenge 2>&1 | tail -5 && cargo build 2>&1 | tail -5`
Expected: test PASS; build `Finished` with zero warnings.

- [ ] **Step 7: Commit**

```bash
git add backend/src/acme_client/client.rs
git commit -m "feat(acme-client): reuse valid LE authorization, skip redundant TXT

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Migration + `renews_cert_id` on the order model

**Files:**
- Create: `backend/migrations/14-acmeclientrenewal/up.sql`
- Create: `backend/migrations/14-acmeclientrenewal/down.sql`
- Modify: `backend/src/acme_client/types.rs` (`AcmeClientOrder`)
- Modify: `backend/src/db.rs` (row mapper, both SELECTs, `insert_acme_client_order`)

**Interfaces:**
- Produces: `AcmeClientOrder.renews_cert_id: Option<i64>`; `insert_acme_client_order(provider_id, domain, include_wildcard, order_url, txt_records, expires_at, renews_cert_id: Option<i64>)`.

- [ ] **Step 1: Create the migration**

`backend/migrations/14-acmeclientrenewal/up.sql`:

```sql
ALTER TABLE acme_client_orders ADD COLUMN renews_cert_id INTEGER;
```

`backend/migrations/14-acmeclientrenewal/down.sql`:

```sql
ALTER TABLE acme_client_orders DROP COLUMN renews_cert_id;
```

- [ ] **Step 2: Add the field to `AcmeClientOrder`**

In `backend/src/acme_client/types.rs`, add to the `AcmeClientOrder` struct (after `expires_at`):

```rust
    pub renews_cert_id: Option<i64>,
```

- [ ] **Step 3: Update the row mapper**

In `backend/src/db.rs`, `acme_client_order_from_row`, add after `expires_at: row.get(10)?,`:

```rust
        renews_cert_id: row.get(11)?,
```

- [ ] **Step 4: Update both SELECT column lists**

In `backend/src/db.rs`, in BOTH `get_acme_client_order` and `get_all_acme_client_orders`, change the column list from `... created_on, expires_at \` to `... created_on, expires_at, renews_cert_id \` (append `, renews_cert_id` before the ` FROM acme_client_orders`).

- [ ] **Step 5: Update `insert_acme_client_order`**

In `backend/src/db.rs`, change the signature and INSERT:

```rust
    pub(crate) async fn insert_acme_client_order(
        &self,
        provider_id: i64,
        domain: String,
        include_wildcard: bool,
        order_url: Option<String>,
        txt_records: &[TxtRecord],
        expires_at: Option<i64>,
        renews_cert_id: Option<i64>,
    ) -> Result<AcmeClientOrder> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
        let txt_json = serde_json::to_string(txt_records)?;
        let id = db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO acme_client_orders (provider_id, domain, include_wildcard, status, order_url, txt_records, created_on, expires_at, renews_cert_id) \
                 VALUES (?1, ?2, ?3, 'pending_dns', ?4, ?5, ?6, ?7, ?8)",
                params![provider_id, domain, include_wildcard, order_url, txt_json, now, expires_at, renews_cert_id],
            )?;
            Ok::<i64, anyhow::Error>(conn.last_insert_rowid())
        })?;
        self.get_acme_client_order(id).await
    }
```

- [ ] **Step 6: Fix the existing caller in the create route (compile-break)**

In `backend/src/acme_client/routes.rs`, `create_acme_client_order`, the existing `state.db.insert_acme_client_order(...)` call now needs the extra arg. For this task pass `None` (Task 4 wires the real value):

```rust
    let order = state.db.insert_acme_client_order(
        provider.id, req.domain.clone(), req.include_wildcard,
        Some(created.order_url), &created.txt_records, created.expires_at, None,
    ).await?;
```

- [ ] **Step 7: Fix the existing db test caller (compile-break)**

In `backend/src/db.rs` test `acme_client_order_crud` (~line 1395), the `db.insert_acme_client_order(...)` call needs the extra trailing `None`. Add `, None` as the final argument.

- [ ] **Step 8: Build + run db tests (migration applies on a fresh test DB)**

Run: `cd backend && cargo build 2>&1 | tail -5 && cargo test --lib acme_client_order_crud 2>&1 | tail -6`
Expected: build clean zero warnings; test PASS (the fresh in-memory DB runs all migrations incl. 14, so the new column exists).

- [ ] **Step 9: Commit**

```bash
git add backend/migrations/14-acmeclientrenewal backend/src/acme_client/types.rs backend/src/db.rs backend/src/acme_client/routes.rs
git commit -m "feat(acme-client): add renews_cert_id column to orders

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: In-place cert renewal (db methods + issue route branch)

**Files:**
- Modify: `backend/src/db.rs` (3 new methods + tests)
- Modify: `backend/src/acme_client/routes.rs` (`issue_acme_client_order` in-place branch)

**Interfaces:**
- Consumes: `AcmeClientOrder.renews_cert_id` (Task 2), `insert_acme_client_certificate` (existing), `pack_issued_certificate` (existing).
- Produces:
  - `update_acme_client_certificate_in_place(&self, cert_id: i64, pkcs12_der: Vec<u8>, valid_until: i64) -> Result<()>`
  - `get_acme_client_order_by_cert_id(&self, cert_id: i64) -> Result<Option<AcmeClientOrder>>`
  - `get_active_renewal_order_for_cert(&self, cert_id: i64) -> Result<Option<AcmeClientOrder>>`

- [ ] **Step 1: Write the failing test**

Add to `backend/src/db.rs` test module (next to `acme_client_order_crud`). It exercises in-place update + the two lookups. Reuse the existing test setup pattern (`crate::db::tests::…` — mirror `acme_client_order_crud` for DB construction and a provider insert):

```rust
    #[tokio::test]
    async fn acme_client_renewal_helpers() {
        let db = mem_db().await;
        // FK: user_certificates.user_id -> users(id); acme_client_orders.cert_id -> user_certificates(id).
        let user = db.insert_user(User {
            id: -1,
            name: "admin".into(),
            email: "a@b.c".into(),
            password_hash: None,
            oidc_id: None,
            role: UserRole::Admin,
        }).await.unwrap();
        let provider = db.insert_acme_client_provider(
            "le".into(), "https://example/dir".into(), "a@b.c".into(), None, None,
        ).await.unwrap();

        // Insert a cert row to renew in place.
        let cert_id = db.insert_acme_client_certificate(
            crate::data::objects::Name::from("example.com"),
            vec![1, 2, 3], "".into(), 1_000, user.id, provider.id,
        ).await.unwrap();

        // Source order that produced this cert.
        let src = db.insert_acme_client_order(
            provider.id, "example.com".into(), false, Some("https://o/1".into()), &[], None, None,
        ).await.unwrap();
        db.update_acme_client_order_status(src.id, "valid", Some(cert_id), None).await.unwrap();
        let found = db.get_acme_client_order_by_cert_id(cert_id).await.unwrap();
        assert_eq!(found.map(|o| o.id), Some(src.id));

        // No active renewal order yet.
        assert!(db.get_active_renewal_order_for_cert(cert_id).await.unwrap().is_none());
        // Create a renewal order (pending_dns) and confirm the guard sees it.
        let ren = db.insert_acme_client_order(
            provider.id, "example.com".into(), false, Some("https://o/2".into()), &[], None, Some(cert_id),
        ).await.unwrap();
        assert_eq!(db.get_active_renewal_order_for_cert(cert_id).await.unwrap().map(|o| o.id), Some(ren.id));

        // In-place update keeps the id, bumps valid_until.
        db.update_acme_client_certificate_in_place(cert_id, vec![9, 9], 5_000).await.unwrap();
        let certs = db.get_user_certs(None, None, None).await.unwrap();
        let c = certs.iter().find(|c| c.id == cert_id).unwrap();
        assert_eq!(c.valid_until, 5_000);
    }
```

`mem_db()`, `insert_user`, `User`, and `UserRole` are already used by sibling tests in this module (see `acme_client_order_crud` and the cert tests). The seeded provider `id=1` from migration 13 also exists, but this test inserts its own provider for clarity.

- [ ] **Step 2: Run to verify it fails**

Run: `cd backend && cargo test --lib acme_client_renewal_helpers 2>&1 | tail -15`
Expected: FAIL — `no method named get_acme_client_order_by_cert_id` (etc.).

- [ ] **Step 3: Add the three db methods**

In `backend/src/db.rs`, add near the other acme_client methods:

```rust
    pub(crate) async fn update_acme_client_certificate_in_place(
        &self,
        cert_id: i64,
        pkcs12_der: Vec<u8>,
        valid_until: i64,
    ) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "UPDATE user_certificates SET data = ?1, valid_until = ?2, created_on = ?3 WHERE id = ?4",
                params![pkcs12_der, valid_until, now, cert_id],
            )?;
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    pub(crate) async fn get_acme_client_order_by_cert_id(&self, cert_id: i64) -> Result<Option<AcmeClientOrder>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, provider_id, domain, include_wildcard, status, order_url, txt_records, cert_id, error, created_on, expires_at, renews_cert_id \
                 FROM acme_client_orders WHERE cert_id = ?1 ORDER BY id DESC LIMIT 1",
            )?;
            let mut rows = stmt.query(params![cert_id])?;
            match rows.next()? {
                Some(row) => Ok(Some(acme_client_order_from_row(row)?)),
                None => Ok(None),
            }
        })
    }

    pub(crate) async fn get_active_renewal_order_for_cert(&self, cert_id: i64) -> Result<Option<AcmeClientOrder>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, provider_id, domain, include_wildcard, status, order_url, txt_records, cert_id, error, created_on, expires_at, renews_cert_id \
                 FROM acme_client_orders WHERE renews_cert_id = ?1 AND status IN ('pending_dns','ready') ORDER BY id DESC LIMIT 1",
            )?;
            let mut rows = stmt.query(params![cert_id])?;
            match rows.next()? {
                Some(row) => Ok(Some(acme_client_order_from_row(row)?)),
                None => Ok(None),
            }
        })
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && cargo test --lib acme_client_renewal_helpers 2>&1 | tail -6`
Expected: PASS.

- [ ] **Step 5: Wire the in-place branch into the issue route**

In `backend/src/acme_client/routes.rs`, `issue_acme_client_order`, replace the `Ok(issued) => { let inner = async { ... }.await; ... }` inner block so it updates in place when the order is a renewal. The `inner` async body becomes:

```rust
            let inner = async {
                let packed = client::pack_issued_certificate(&issued.certificate_pem, &issued.private_key_pem, "")
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let result_cert_id = if let Some(renew_id) = order.renews_cert_id {
                    // Renewal: update the existing certificate in place (same id).
                    state.db.update_acme_client_certificate_in_place(renew_id, packed.pkcs12_der, packed.valid_until)
                        .await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    renew_id
                } else {
                    let cert_name = if order.include_wildcard {
                        crate::data::objects::Name::from(
                            format!("{}, *.{}", order.domain, order.domain).as_str()
                        )
                    } else {
                        crate::data::objects::Name::from(order.domain.as_str())
                    };
                    state.db.insert_acme_client_certificate(
                        cert_name,
                        packed.pkcs12_der, "".into(), packed.valid_until, auth._claims.id, provider.id,
                    ).await.map_err(|e| anyhow::anyhow!(e.to_string()))?
                };
                state.db.update_acme_client_order_status(id, "valid", Some(result_cert_id), None).await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                Ok::<_, anyhow::Error>(())
            }.await;
```

- [ ] **Step 6: Build + tests**

Run: `cd backend && cargo build 2>&1 | tail -5 && cargo test --lib acme_client 2>&1 | tail -6`
Expected: build clean zero warnings; all acme_client tests PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src/db.rs backend/src/acme_client/routes.rs
git commit -m "feat(acme-client): renew certificate in place when order carries renews_cert_id

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Thread `renews_cert_id` through the create-order request (backend + frontend)

**Files:**
- Modify: `backend/src/acme_client/types.rs` (`CreateOrderRequest`)
- Modify: `backend/src/acme_client/routes.rs` (`create_acme_client_order`)
- Modify: `frontend/src/types/AcmeClient.ts` (`CreateOrderRequest`)
- Modify: `frontend/src/stores/acmeClient.ts` (pass field through — usually already spread)
- Modify: `frontend/src/components/AcmeClientTab.vue` (renew button sets it)

**Interfaces:**
- Consumes: `insert_acme_client_order(..., renews_cert_id)` (Task 2).
- Produces: `CreateOrderRequest.renews_cert_id: Option<i64>` (BE) / `renews_cert_id?: number | null` (FE).

- [ ] **Step 1: Backend request field + passthrough**

In `backend/src/acme_client/types.rs`, add to `CreateOrderRequest`:

```rust
    #[serde(default)]
    pub renews_cert_id: Option<i64>,
```

In `backend/src/acme_client/routes.rs`, `create_acme_client_order`, change the insert call's final arg from `None` (set in Task 2 step 6) to `req.renews_cert_id`:

```rust
    let order = state.db.insert_acme_client_order(
        provider.id, req.domain.clone(), req.include_wildcard,
        Some(created.order_url), &created.txt_records, created.expires_at, req.renews_cert_id,
    ).await?;
```

- [ ] **Step 2: Backend build**

Run: `cd backend && cargo build 2>&1 | tail -5`
Expected: `Finished`, zero warnings.

- [ ] **Step 3: Frontend type**

In `frontend/src/types/AcmeClient.ts`, add to `CreateOrderRequest`:

```ts
  renews_cert_id?: number | null
```

- [ ] **Step 4: Frontend renew button wiring**

In `frontend/src/components/AcmeClientTab.vue`:

- Add `renews_cert_id` to the `orderForm` reactive object (`frontend/src/components/AcmeClientTab.vue:402`), typed `number | null`, default `null`.
- In `openNewOrderModal(renewFrom?: AcmeClientOrder)`, set it: in the `if (renewFrom)` branch add `orderForm.renews_cert_id = renewFrom.cert_id ?? null`; in the `else` branch add `orderForm.renews_cert_id = null`.
- In `closeNewOrderModal`, reset `orderForm.renews_cert_id = null`.
- In `submitNewOrder`, ensure the `store.newOrder({...})` payload includes `renews_cert_id: orderForm.renews_cert_id`.

The `orderForm` type annotation gains `renews_cert_id: number | null` and the three reset sites set it to `null`; the `renewFrom` path sets it to `renewFrom.cert_id ?? null`.

- [ ] **Step 5: Frontend store passthrough**

In `frontend/src/stores/acmeClient.ts`, `newOrder(req: CreateOrderRequest)` already forwards `req` to `api.createOrder(req)`; confirm no field whitelist strips `renews_cert_id`. If `submitNewOrder` builds an explicit object, make sure it includes `renews_cert_id`. No code change if it already spreads/forwards the full request.

- [ ] **Step 6: Frontend type-check**

Run: `cd frontend && npx vue-tsc --noEmit 2>&1 | tail -6`
Expected: `ok`.

- [ ] **Step 7: Commit**

```bash
git add backend/src/acme_client/types.rs backend/src/acme_client/routes.rs frontend/src/types/AcmeClient.ts frontend/src/stores/acmeClient.ts frontend/src/components/AcmeClientTab.vue
git commit -m "feat(acme-client): manual renew reuses authz and renews in place via renews_cert_id

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Semi-auto renewal in the expiry ticker (+ latent internal-CA bug fix)

**Files:**
- Modify: `backend/src/notification/notifier.rs`
- Modify: `backend/src/lib.rs` (pass `settings` into `watch_expiry`)

**Interfaces:**
- Consumes: `client::create_order`, `client::issue_order`, `client::pack_issued_certificate`; `db.get_acme_client_provider`, `db.update_acme_client_provider_credentials`, `db.insert_acme_client_order(...renews_cert_id)`, `db.get_acme_client_order_by_cert_id`, `db.get_active_renewal_order_for_cert`, `db.update_acme_client_certificate_in_place`, `db.update_acme_client_order_status`; `settings.get_acme_dns_resolver()`, `settings.get_acme_accept_invalid_certs()`; `mailer.notify_renewed_certificate`, `mailer.notify_old_certificate`.
- Produces: `async fn handle_acme_renewal(cert, db, settings, mailer_mutex) -> Result<()>`.

- [ ] **Step 1: Pass `settings` into `watch_expiry`**

In `backend/src/notification/notifier.rs`, change the signature:

```rust
pub(crate) async fn watch_expiry(db: VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>, settings: crate::settings::Settings) {
```

In `backend/src/lib.rs:182-184`, change the spawn to pass a clone (`Settings` is `Clone`, Arc-backed):

```rust
    tokio::spawn(async move {
        watch_expiry(db.clone(), mailer.clone(), app_state.settings.clone()).await;
    });
```

- [ ] **Step 2: Route ACME certs away from the internal-CA path + add the 30-day ACME window**

In `backend/src/notification/notifier.rs`, replace the ticker's per-cert loop (the `for cert in certs.iter().filter(...)` block) with routing that (a) keeps internal-CA certs on the existing `handle_expiry` + reset path, (b) sends ACME certs with `Renew`/`RenewAndNotify` to the new path on a 30-day window without resetting `renew_method`, and (c) keeps ACME `Notify` certs on the reminder path (7-day window, reset once):

```rust
        if let Ok(certs) = db.get_user_certs(None, None, Some(false)).await {
            let now = chrono::Utc::now().timestamp_millis();
            let in_a_week = now + 1000 * 60 * 60 * 24 * 7;
            let in_30_days = now + 1000 * 60 * 60 * 24 * 30;
            for cert in certs.iter() {
                if cert.renew_method == CertificateRenewMethod::None {
                    continue;
                }
                if cert.acme_provider_id.is_some() {
                    // ACME certificates never go through the internal-CA renewal path.
                    match cert.renew_method {
                        CertificateRenewMethod::Renew | CertificateRenewMethod::RenewAndNotify => {
                            if cert.valid_until < in_30_days {
                                // Do NOT reset renew_method — auto-renew must keep firing.
                                if let Err(e) = handle_acme_renewal(cert, &db, &settings, mailer_mutex.clone()).await {
                                    info!("ACME renewal for cert {} failed: {e}", cert.id);
                                }
                            }
                        }
                        CertificateRenewMethod::Notify => {
                            if cert.valid_until < in_a_week
                                && handle_expiry(cert, &db, mailer_mutex.clone()).await.is_ok()
                            {
                                let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
                            }
                        }
                        CertificateRenewMethod::None => {}
                    }
                } else if cert.valid_until < in_a_week
                    && handle_expiry(cert, &db, mailer_mutex.clone()).await.is_ok()
                {
                    let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
                }
            }
        } else {
            info!("Failed to get certificates from database.");
        }
```

- [ ] **Step 3: Add `handle_acme_renewal`**

In `backend/src/notification/notifier.rs`, add the function (import what it needs at the top: `crate::acme_client::client`, `MailMessage` is already used). Full body:

```rust
async fn handle_acme_renewal(
    cert: &Certificate,
    db: &VaulTLSDB,
    settings: &crate::settings::Settings,
    mailer_mutex: Arc<Mutex<Option<Mailer>>>,
) -> Result<(), anyhow::Error> {
    // Dedup guard: don't create a second renewal order while one is still in flight.
    if db.get_active_renewal_order_for_cert(cert.id).await?.is_some() {
        return Ok(());
    }

    // Derive domain/provider/wildcard from the order that originally produced this cert.
    let source = db
        .get_acme_client_order_by_cert_id(cert.id)
        .await?
        .ok_or_else(|| anyhow!("no source order found for cert {}", cert.id))?;
    let provider = db.get_acme_client_provider(source.provider_id).await?;

    let created = client::create_order(&provider, &source.domain, source.include_wildcard).await?;
    if let Some(creds) = created.account_credentials {
        db.update_acme_client_provider_credentials(provider.id, creds).await?;
    }
    let order = db
        .insert_acme_client_order(
            provider.id,
            source.domain.clone(),
            source.include_wildcard,
            Some(created.order_url.clone()),
            &created.txt_records,
            created.expires_at,
            Some(cert.id),
        )
        .await?;

    if created.txt_records.is_empty() {
        // Authorization still valid at the CA — renew unattended.
        let resolver = settings.get_acme_dns_resolver();
        let accept_invalid = settings.get_acme_accept_invalid_certs();
        let issued = client::issue_order(
            &provider,
            &created.order_url,
            &source.domain,
            &created.txt_records,
            &resolver,
            accept_invalid,
        )
        .await?;
        let packed = client::pack_issued_certificate(&issued.certificate_pem, &issued.private_key_pem, "")?;
        db.update_acme_client_certificate_in_place(cert.id, packed.pkcs12_der, packed.valid_until).await?;
        db.update_acme_client_order_status(order.id, "valid", Some(cert.id), None).await?;

        if cert.renew_method == CertificateRenewMethod::RenewAndNotify {
            let user = db.get_user(cert.user_id).await?;
            let mail = MailMessage {
                to: format!("{} <{}>", user.name, user.email),
                username: user.name,
                certificate: cert.clone(),
            };
            tokio::spawn(async move {
                if let Some(mailer) = &mut *mailer_mutex.lock().await {
                    let _ = mailer.notify_renewed_certificate(mail).await;
                }
            });
        }
    } else {
        // Fresh challenge needed — leave the order pending_dns and tell the user to publish TXT.
        info!(
            "ACME renewal for cert {} needs new TXT records; order {} left pending_dns.",
            cert.id, order.id
        );
        let user = db.get_user(cert.user_id).await?;
        let mail = MailMessage {
            to: format!("{} <{}>", user.name, user.email),
            username: user.name,
            certificate: cert.clone(),
        };
        tokio::spawn(async move {
            if let Some(mailer) = &mut *mailer_mutex.lock().await {
                let _ = mailer.notify_old_certificate(mail).await;
            }
        });
    }

    Ok(())
}
```

- [ ] **Step 4: Build + full acme test suite**

Run: `cd backend && cargo build 2>&1 | tail -8 && cargo test --lib acme_client 2>&1 | tail -6`
Expected: build `Finished`, ZERO warnings; tests PASS. If `use` items are missing (e.g. `client`, `Certificate`, `anyhow`), add them to the top of `notifier.rs`.

- [ ] **Step 5: Commit**

```bash
git add backend/src/notification/notifier.rs backend/src/lib.rs
git commit -m "feat(acme-client): semi-auto renewal in expiry ticker; stop routing ACME certs through internal CA

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Manual verification (after all tasks)

1. `cd backend && cargo build && cargo test --lib acme_client` → zero warnings, green.
2. `cd frontend && npx vue-tsc --noEmit` → `ok`.
3. On LE staging with a real bind9 domain:
   - Issue a cert; set its renew method to Renew/RenewAndNotify.
   - Manual renew via the UI button while the authz is still valid (<30 days since issuance): modal shows NO TXT (empty), issuance succeeds, the SAME cert row is updated (id unchanged, valid_until bumped) — no second cert.
   - Manual renew after the authz window: modal shows fresh TXT; publish, Check & Issue; same cert updated in place.
   - Ticker: force `valid_until` within 30 days (or shorten via staging); confirm at most one renewal order per cert per cycle (dedup guard), unattended renew when authz valid, pending_dns + email when TXT needed.
4. Confirm an ACME cert with renew_method=Renew is NOT re-issued by the internal CA (ca_id stays NULL, acme_provider_id stays set).

## Notes on scope / compatibility

- Internal-CA renewal and one-shot issue behavior are unchanged except that ACME certs are now excluded from the internal-CA path (the latent bug fix).
- Migration is additive; pre-existing orders (`renews_cert_id = NULL`) keep INSERT-on-issue behavior.
- No key reuse; each renewal produces a fresh key via instant-acme `finalize()`.
