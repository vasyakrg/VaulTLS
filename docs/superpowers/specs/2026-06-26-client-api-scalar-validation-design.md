# Client-facing API: Scalar docs, certificate validation, CA endpoint polish — Design

**Date:** 2026-06-26
**Scope:** backend only (Rust, Rocket 0.5.1). Frontend untouched.
**Status:** approved (design), pending implementation plan.

## Goal

Make the VaulTLS HTTP API friendlier for programmatic clients, in three independent
slices that ship together:

1. **Scalar** interactive API reference (replacing RapiDoc), self-hosted (no CDN).
2. A **public certificate-validation endpoint** keyed by serial number.
3. **Polish of the already-public CA download endpoints** (format selection, file
   names/MIME, fullchain bundle).

Service accounts / API tokens (Bearer auth for automated issuance) are explicitly
**out of scope** for this iteration — they are a separate, larger feature.

## Context (current state, verified)

- OpenAPI spec is already generated via `rocket_okapi` 0.9 + `schemars` 0.8 and served
  at `GET /api/openapi.json`. The interactive UI is currently **RapiDoc**, mounted at
  `/api/` via `make_rapidoc(...)` in `backend/src/lib.rs`.
- Auth is cookie-JWT only (`auth_token` private cookie, `jsonwebtoken`); guards
  `Authenticated` / `AuthenticatedPrivileged` in `backend/src/auth/session_auth.rs`.
  No Bearer support (irrelevant to this scope — new endpoints are public).
- CA download endpoints are **already public** (no guard):
  `GET /api/certificates/ca/download`, `/ca/ssh/download`, `/ca/<id>/download`,
  `/ca/<id>/crl?<format>`. CRL already supports `format=der|pem` via a `DataFormat` type.
- `user_certificates` columns (verified in `backend/migrations/`): `serial_hex TEXT`
  (added in `10-acme`, indexed by `idx_user_certificates_serial_hex`), `created_on
  INTEGER NOT NULL` (issuance / not-before), `valid_until INTEGER NOT NULL` (not-after),
  `revoked_at INTEGER` (nullable), `ca_id INTEGER`. **No migration needed** — all data
  for validation already exists.
- DB exposes `get_cert_id_by_serial_hex(serial)` which **excludes** revoked certs — not
  reusable for status (we need revoked ones too), so a new query is required.

## Architecture

Three slices, one backend change set. Files touched:

| File | Change |
|------|--------|
| `backend/Cargo.toml` | add `scalar_api_reference`; remove RapiDoc usage |
| `backend/src/lib.rs` | swap RapiDoc routes for Scalar routes; mount new endpoints |
| `backend/src/api.rs` | new `validate` endpoint; CA download polish (format/filename/fullchain) |
| `backend/src/db.rs` | new `get_cert_status_by_serial_hex` |
| `backend/src/data/enums.rs` | new `CertStatus` enum |
| `backend/src/data/api.rs` | new `CertStatusResponse` type |
| `backend/tests/api/*` | new integration tests |

### Slice 1 — Scalar UI (self-hosted)

- Add dependency `scalar_api_reference` (provides `scalar_html`, `get_asset_with_mime`,
  with the JS bundle embedded in the binary).
- In `lib.rs`, remove the `make_rapidoc(...)` mount and the RapiDoc config import. Mount
  two routes instead:
  - `GET /api/` → returns `scalar_html(config, Some("/api/scalar.js"))` where
    `config = {"url": "/api/openapi.json", "theme": "purple"}` (theme final value chosen
    in plan; purple matches the app primary `#6e56cf`).
  - `GET /api/scalar.js` → returns the embedded asset via `get_asset_with_mime("scalar.js")`
    with the correct `Content-Type`.
- `GET /api/openapi.json` (from `openapi_get_routes!`) is unchanged.
- No external CDN is contacted — required for closed/offline infra.

### Slice 2 — Public certificate validation

- `db.rs`: `get_cert_status_by_serial_hex(serial_hex: String) -> Result<Option<CertStatusRow>>`
  returning `created_on`, `valid_until`, `revoked_at`, `ca_id` (includes revoked certs).
  Uses the existing `serial_hex` index.
- `data/enums.rs`: `enum CertStatus { Valid, Revoked, Expired, NotYetValid, Unknown }`
  (`Serialize`, `JsonSchema`).
- `data/api.rs`: `CertStatusResponse { serial: String, status: CertStatus,
  not_before: Option<i64>, not_after: Option<i64>, revoked_at: Option<i64>,
  ca_id: Option<i64> }` (epoch ms, matching existing timestamp convention).
- `api.rs`: `GET /certificates/validate?serial=<hex>` — **no guard**, `#[openapi]`.
  Status logic (evaluated in order): not found → `Unknown`; `revoked_at` present →
  `Revoked`; `now > valid_until` → `Expired`; `now < created_on` → `NotYetValid`;
  else `Valid`. For `Unknown`, timestamp/ca fields are `null`.
- **Privacy:** response intentionally omits CN/SAN/owner — only status + dates + ca_id.
  Serial is normalized (lowercase hex, strip colons/whitespace) before lookup.

### Slice 3 — CA endpoint polish

- **Format selection:** add `?format=pem|der` to `/ca/download`, `/ca/ssh/download`,
  `/ca/<id>/download`, reusing the existing `DataFormat` type used by CRL. Defaults
  preserve current behaviour (TLS → PEM, SSH → `.pub`).
- **File name + MIME:** set `Content-Disposition: attachment; filename="ca.<ext>"`
  (`crt`/`pem`/`der` per format) and the correct `Content-Type`
  (`application/x-pem-file` for PEM, `application/pkix-cert` for DER). SSH CA keeps its
  `.pub`/`application/octet-stream` shape.
- **Fullchain:** `GET /certificates/ca/<id>/fullchain` — returns the chain
  (root + intermediates) as a single concatenated PEM. For a self-signed internal CA the
  chain is the CA itself; for imported CAs, walk `ca_certificates` by issuer/subject to
  assemble the chain. Public (no guard), `#[openapi]`.

## Error handling

- `validate` with missing/empty `serial` → `400 BadRequest`; unknown serial → `200` with
  `status: "unknown"` (not 404 — clients distinguish "not ours" from "bad request").
- CA endpoints with invalid `format` → `400 BadRequest`.
- `fullchain` for unknown `<id>` → `404`.
- All new public endpoints must not leak internal errors (map to generic `ApiError`).

## Testing

Integration tests in `backend/tests/api/` (do not break existing suite):

- **validate:** issue a cert → look up by its `serial_hex` → `Valid` with correct dates;
  revoke it → `Revoked` with `revoked_at`; craft expired/not-yet-valid cases → `Expired`/
  `NotYetValid`; random serial → `Unknown`; missing/garbage serial → `400`.
- **CA download:** `format=pem` and `format=der` return correct bytes, `Content-Type`,
  and `Content-Disposition` filename; invalid format → `400`.
- **fullchain:** internal CA → single PEM; imported CA with intermediate → concatenated
  chain in correct order; unknown id → `404`.
- **Scalar:** `GET /api/` → 200 HTML referencing `/api/scalar.js` and `/api/openapi.json`;
  `GET /api/scalar.js` → 200 with JS MIME; `GET /api/openapi.json` still 200.

## Out of scope (next iteration)

- Service accounts / API keys / Bearer auth for automated issuance.
- Full OCSP responder (RFC 6960) — CRL + the validation endpoint cover the need.
- pgcrypto / PostgreSQL (dropped: too much work for a single-writer app on SQLite).
