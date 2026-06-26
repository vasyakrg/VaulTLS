# Service accounts + Bearer/JWT for machine access — Design

**Date:** 2026-06-26
**Scope:** backend (Rust/Rocket) + frontend (Vue 3) management UI.
**Status:** approved (design), pending implementation plan.

## Goal

Let automated clients (CI, scripts) authenticate to the VaulTLS API and pull/issue
certificates without a browser cookie. A **service account** (client_id + secret) is
exchanged for a short-lived JWT, presented as `Authorization: Bearer`. Permissions are
granular scopes; each service account is bound to one owning user.

## Decisions (agreed)

- **Mechanism:** service account `client_id` + `secret` → `POST /auth/token` → short JWT
  (1 h) in the response body → client sends `Authorization: Bearer <jwt>`.
- **Scopes (this iteration):** `cert:read`, `cert:issue`. (`cert:revoke`, `ca:manage`
  deliberately deferred — the model is extensible.)
- **Binding:** each service account is tied to one `user_id` (owner). It issues certs
  only for that user and reads/downloads only that user's certs. Minimizes blast radius.
- **Management UI:** in the Users section, a per-user modal (Admin only).

## Context (verified)

- Auth today is cookie-only JWT (HS256, 1 h, signing key from `VAULTLS_API_SECRET` via
  `settings.get_jwt_key()`). `Claims { jti, id, role, exp }`. Token read **only** from the
  private `auth_token` cookie in `authenticate_auth_token` (`auth/session_auth.rs`).
- `JTI_STORE` is an in-memory `HashSet<String>` of active jti — human logout removes the
  jti; a process restart empties it (all cookie tokens invalidated).
- Guards: `Authenticated` (any valid token), `AuthenticatedPrivileged` (role == Admin).
- `generate_token(jwt_key, user_id, role)` builds the cookie JWT.
- Cert ownership checks compare `cert.user_id == claims.id` (or Admin). Issuance
  (`POST /certificates`) requires `AuthenticatedPrivileged`.
- Last migration is `11-import`; next is `12-serviceaccounts`.
- Frontend: `UserTab.vue` (DataTable + `BaseModal` for create/edit/delete), `ApiClient`
  (`baseURL = origin + '/api'`, `withCredentials: true`), Pinia stores, PrimeVue 4,
  i18n locales en/es (fr empty). Admin-only via `auth.isAdmin`.

## Architecture

### 1. Data model — migration `12-serviceaccounts`

```sql
CREATE TABLE service_accounts (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    secret_hash  TEXT NOT NULL,
    user_id      INTEGER NOT NULL,
    scopes       TEXT NOT NULL,          -- CSV, e.g. "cert:read,cert:issue"
    created_at   INTEGER NOT NULL,       -- epoch ms
    last_used_at INTEGER,                -- epoch ms, nullable
    revoked      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_service_accounts_client_id ON service_accounts(client_id);
```

`client_id` is a public random id (e.g. `svc_` + 16 hex). `secret` is a high-entropy random
string shown once; only its argon2 hash is stored (reuse `Password::new_server_hash` /
`verify`, or a dedicated argon2 helper). Deleting the owning user cascades.

### 2. JWT for services

Extend `Claims` with an optional service block (absent/None for human tokens):

```rust
pub struct ServiceClaims { pub account_id: i64, pub scopes: Vec<String> }
// Claims { jti, id, role, exp, service: Option<ServiceClaims> }
```

- A service JWT carries `id = owner user_id`, `role = User`, `service = Some{account_id,
  scopes}`, `exp` = now + 1 h. Because `id` is the owner, existing ownership checks
  (`cert.user_id == claims.id`) already scope a service to its owner's certs.
- `generate_service_token(jwt_key, owner_user_id, account_id, scopes)` mirrors
  `generate_token` but sets the service block and `role = User`.
- **Statefulness:** human tokens stay stateful (jti in `JTI_STORE`, instant logout).
  Service tokens are **stateless** — NOT inserted into `JTI_STORE`, validated by signature
  + exp only, so they survive a restart. Revocation is via the `revoked` flag (no new
  tokens issued) plus the short 1 h exp (an active token lives at most 1 h after revoke).
  `authenticate_auth_token` must skip the JTI check when `claims.service.is_some()`.

### 3. Token acceptance (cookie OR Bearer)

`authenticate_auth_token(request)` is extended: take the token from the private
`auth_token` cookie, else from an `Authorization: Bearer <jwt>` header. Decode/validate as
today; for service tokens skip the `JTI_STORE` membership check. Guards `Authenticated` /
`AuthenticatedPrivileged` are unchanged in shape — they now transparently accept Bearer.

### 4. Token exchange endpoint

`POST /auth/token` (public, `#[openapi]`): body `{ client_id, secret }`.
- Look up by `client_id`; if not found / `revoked` / secret mismatch → `401` (uniform
  message, no oracle distinguishing the cases).
- On success: `generate_service_token(...)`, update `last_used_at`, return
  `{ access_token, token_type: "Bearer", expires_in: 3600, scopes }`.

### 5. Authorization on protected endpoints

A small helper on `Claims` decides scope access uniformly:

```rust
// human Admin → allowed for everything; human User → allowed for own-cert reads;
// service → allowed iff the required scope is in claims.service.scopes
fn require_scope(&self, scope: &str) -> Result<(), ApiError>
```

- **Issue** (`POST /certificates`): change the guard from `AuthenticatedPrivileged` to
  `Authenticated`, then in-handler `claims.require_scope("cert:issue")` — passes for human
  Admin OR a service with `cert:issue`. For a service token, **force** the new cert's
  `user_id = claims.id` (ignore/override any other target), so a service cannot issue for
  another user.
- **Read** (`GET /certificates`, `/certificates/<id>/download`, `/certificates/<id>/password`):
  keep `Authenticated`; if the token is a service token, require `cert:read`. Ownership is
  already enforced via `claims.id == owner`.
- Endpoints NOT in scope for services (user management, settings, CA management, revoke)
  stay `AuthenticatedPrivileged`; a service token has `role = User` so it is rejected there.

### 6. Management endpoints (Admin only)

- `POST /users/<id>/service-accounts` — body `{ name, scopes: [..] }`. Validates scopes
  against the allowed set, generates `client_id` + `secret`, stores the hash, returns
  `{ id, name, client_id, secret, scopes }` — **secret present only in this response**.
- `GET /users/<id>/service-accounts` — list for that user (no secret/hash): `{ id, name,
  client_id, scopes, created_at, last_used_at, revoked }`.
- `DELETE /service-accounts/<sid>` — set `revoked = 1` (soft revoke; preserves audit of
  `last_used_at`).

### 7. Management UI (Users section, Admin only)

- `UserTab.vue`: add a row-action button **"Service accounts"** (`pi pi-key`) next to
  Edit/Delete → opens `ServiceAccountsModal` for that user. Edit stays the profile modal.
- `ServiceAccountsModal.vue` (built on `BaseModal`, custom footer):
  - **List** (DataTable): name, client_id, scopes (Tags), created_at, last_used_at, status
    (active/revoked), a "Revoke" button per row.
  - **Create**: `InputText` name + `Checkbox` per scope (cert:read, cert:issue) → submit.
  - **After create**: a highlighted block shows `client_id` and the one-time `secret` with
    a copy button (`navigator.clipboard.writeText`) and a "save it now, won't be shown
    again" warning.
- New: `stores/serviceAccounts.ts` (fetchForUser / create / revoke), `api/serviceAccounts.ts`,
  `types/ServiceAccount.ts`, i18n keys `serviceAccounts.*` (en + es).

## Error handling

- `POST /auth/token`: bad/unknown/revoked credentials → `401` (uniform). Malformed body → `400`.
- Service token without the required scope → `403`.
- Service token on an Admin-only endpoint → `403` (role == User).
- Service `cert:issue` always binds to the owner; a target user_id mismatch is silently
  overridden to the owner (never issues for someone else).
- Management endpoints on a non-existent user → `404`.

## Testing

Backend integration tests:
- exchange: valid client_id+secret → JWT with correct scopes; wrong secret / unknown
  client_id / revoked account → 401.
- Bearer acceptance: a service JWT authorizes `GET /certificates` (with `cert:read`); a
  service without `cert:read` → 403; cookie human flow still works unchanged.
- issue: service with `cert:issue` creates a cert bound to its owner; the created cert's
  user_id equals the owner even if another is supplied; service without `cert:issue` → 403.
- ownership: a service for user A cannot download user B's cert.
- management: create returns secret once; list never returns secret/hash; revoke makes
  `/auth/token` fail; all management endpoints reject non-Admin.
- restart resilience (unit-level where feasible): a service token validates without a
  JTI_STORE entry.

Frontend: the modal lists/creates/revokes; secret shown once and copyable; Admin-only.

## Out of scope (later)

- `cert:revoke`, `ca:manage` scopes.
- Per-token expiry/rotation policies beyond the fixed 1 h.
- OIDC-issued service identities.
