# ACME dns-01 Split DNS-Check / Issue Gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the single "Check & Issue" action into a repeatable "Check DNS" (resolver-only, never contacts the CA) and a "Start issuance" button that stays disabled until a DNS check succeeds in the current modal session.

**Architecture:** A new backend endpoint `POST /acme-client/orders/<id>/check-dns` runs only the TXT-visibility lookup and returns a structured `{ok, expected, found, missing, error}` without touching the CA or the order status. A shared `check_txt_records` helper backs both this endpoint and the existing `issue_order` precheck (defense-in-depth). The frontend gates the "Start issuance" button on an ephemeral `dnsOk` ref set by the check.

**Tech Stack:** Rust (Rocket, rocket-okapi, instant-acme, hickory-resolver), Vue 3 + TypeScript (Pinia, PrimeVue), i18n JSON locales.

## Global Constraints

- Backend response DTOs derive `Serialize, Deserialize, JsonSchema` (rocket-okapi requirement).
- New route must be registered in **all three** `openapi_get_routes!` mount lists in `src/lib.rs` (currently near lines 249, 329, 380 — each already lists `issue_acme_client_order`).
- The check endpoint MUST NOT call `set_ready`/finalize and MUST NOT mutate order status.
- Frontend gate state is ephemeral (frontend refs only); no DB migration.
- New i18n keys added to BOTH `frontend/src/locales/en.json` and `frontend/src/locales/es.json`.
- Every backend change compiles clean: `cargo build` from `backend/` with zero warnings.
- Frontend type-check clean: `npx vue-tsc --noEmit` from `frontend/`.
- Work happens on branch `feat/acme-dns-check-gate` (already checked out).

---

### Task 1: Backend pure TXT comparison helper

**Files:**
- Modify: `backend/src/acme_client/client.rs` (add helper + unit test in existing `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `fn missing_txt_values(expected: &[TxtRecord], found: &[String]) -> Vec<String>` — returns the subset of `expected` values not present in `found`, preserving `expected` order.

- [ ] **Step 1: Write the failing test**

Add inside the existing `mod tests` block in `backend/src/acme_client/client.rs`:

```rust
    #[test]
    fn missing_txt_values_reports_only_absent() {
        let expected = vec![
            TxtRecord { name: "_acme-challenge.example.com".into(), value: "aaa".into() },
            TxtRecord { name: "_acme-challenge.example.com".into(), value: "bbb".into() },
        ];
        // Only "aaa" is published.
        let found = vec!["aaa".to_string(), "zzz".to_string()];
        assert_eq!(missing_txt_values(&expected, &found), vec!["bbb".to_string()]);

        // All published → nothing missing.
        let found_all = vec!["bbb".to_string(), "aaa".to_string()];
        assert!(missing_txt_values(&expected, &found_all).is_empty());

        // None published → both missing, in expected order.
        assert_eq!(
            missing_txt_values(&expected, &[]),
            vec!["aaa".to_string(), "bbb".to_string()]
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && cargo test --lib missing_txt_values_reports_only_absent 2>&1 | tail -15`
Expected: FAIL — compile error `cannot find function missing_txt_values`.

- [ ] **Step 3: Write minimal implementation**

Add this free function to `backend/src/acme_client/client.rs` (place it just above `order_identifiers`):

```rust
/// Returns the subset of `expected` TXT values that are NOT present among `found`,
/// preserving the order of `expected`. Pure comparison — no network.
pub(crate) fn missing_txt_values(expected: &[TxtRecord], found: &[String]) -> Vec<String> {
    expected
        .iter()
        .map(|r| r.value.clone())
        .filter(|v| !found.iter().any(|f| f == v))
        .collect()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && cargo test --lib missing_txt_values_reports_only_absent 2>&1 | tail -8`
Expected: PASS (`test result: ok. 1 passed`).

- [ ] **Step 5: Commit**

```bash
git add backend/src/acme_client/client.rs
git commit -m "feat(acme-client): pure missing_txt_values helper for TXT comparison

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Backend `check_txt_records` + refactor `issue_order` precheck

**Files:**
- Modify: `backend/src/acme_client/client.rs`

**Interfaces:**
- Consumes: `missing_txt_values` (Task 1); `crate::dns_check::lookup_txt_values(domain, resolver_addr, accept_invalid_certs) -> Result<Vec<String>, String>`.
- Produces:
  - `struct DnsCheckOutcome { pub ok: bool, pub expected: Vec<String>, pub found: Vec<String>, pub missing: Vec<String> }`
  - `async fn check_txt_records(domain: &str, txt_records: &[TxtRecord], resolver_addr: &str, accept_invalid_certs: bool) -> anyhow::Result<DnsCheckOutcome>` — returns `Err` ONLY when the lookup itself fails; otherwise `Ok(outcome)` with `ok = missing.is_empty()`.

- [ ] **Step 1: Add `DnsCheckOutcome` + `check_txt_records`**

Add above `missing_txt_values` in `backend/src/acme_client/client.rs`:

```rust
/// Outcome of a resolver-only TXT visibility check. `ok` is true when every expected
/// record is currently published.
pub(crate) struct DnsCheckOutcome {
    pub ok: bool,
    pub expected: Vec<String>,
    pub found: Vec<String>,
    pub missing: Vec<String>,
}

/// Resolve the `_acme-challenge.<domain>` TXT records via the configured resolver and compare
/// them to `txt_records`. Never contacts the ACME server. Returns `Err` only if the DNS lookup
/// itself fails (network / NXDOMAIN / bad resolver address).
pub(crate) async fn check_txt_records(
    domain: &str,
    txt_records: &[TxtRecord],
    resolver_addr: &str,
    accept_invalid_certs: bool,
) -> Result<DnsCheckOutcome> {
    let found = crate::dns_check::lookup_txt_values(domain, resolver_addr, accept_invalid_certs)
        .await
        .map_err(|e| anyhow!(
            "DNS lookup for _acme-challenge.{domain} failed: {e}. Check your bind9 zone / resolver and try again."
        ))?;
    let missing = missing_txt_values(txt_records, &found);
    let expected = txt_records.iter().map(|r| r.value.clone()).collect();
    Ok(DnsCheckOutcome { ok: missing.is_empty(), expected, found, missing })
}
```

- [ ] **Step 2: Refactor `issue_order` precheck to reuse the helper**

In `backend/src/acme_client/client.rs`, replace the current precheck block (the section starting `// 1. DNS precheck` and ending just before `// 2. Restore account and order.`) with:

```rust
    // 1. DNS precheck — every TXT record must be visible before we tell the ACME server anything.
    //    Uses the admin-configured resolver (VAULTLS_ACME_DNS_RESOLVER) so the pre-check queries the
    //    same nameserver as the ACME server-side validation, not the container's system resolver.
    //    Defense-in-depth: the frontend already gates on a successful check, but never trust it.
    let precheck = check_txt_records(domain, txt_records, resolver_addr, accept_invalid_certs).await?;
    if !precheck.ok {
        let expected_block = precheck
            .expected
            .iter()
            .map(|v| format!("  • {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let found_block = if precheck.found.is_empty() {
            "  (none — no TXT records published at this name)".to_string()
        } else {
            precheck.found.iter().map(|v| format!("  • {v}")).collect::<Vec<_>>().join("\n")
        };
        return Err(anyhow!(
            "TXT records for _acme-challenge.{domain} are not visible in DNS yet.\n\
             Expected:\n{expected_block}\n\
             Currently published:\n{found_block}\n\
             Add the missing records to your bind9 zone, bump the serial, run rndc reload, then retry."
        ));
    }
```

- [ ] **Step 3: Build to verify it compiles**

Run: `cd backend && cargo build 2>&1 | tail -8`
Expected: `Finished` with zero warnings. (If an unused-import warning appears for something the old precheck used, remove it.)

- [ ] **Step 4: Run existing acme_client tests**

Run: `cd backend && cargo test --lib acme_client 2>&1 | tail -6`
Expected: PASS (all previously-passing tests still green).

- [ ] **Step 5: Commit**

```bash
git add backend/src/acme_client/client.rs
git commit -m "refactor(acme-client): shared check_txt_records backs issue precheck

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Backend check-dns endpoint + DTO + route registration

**Files:**
- Modify: `backend/src/acme_client/types.rs` (add `DnsCheckResponse`)
- Modify: `backend/src/acme_client/routes.rs` (add handler)
- Modify: `backend/src/lib.rs` (register route in 3 mount lists)

**Interfaces:**
- Consumes: `client::check_txt_records`, `DnsCheckOutcome` (Task 2); `state.settings.get_acme_dns_resolver()`, `state.settings.get_acme_accept_invalid_certs()`.
- Produces: `DnsCheckResponse { ok: bool, expected: Vec<String>, found: Vec<String>, missing: Vec<String>, error: Option<String> }`; route fn `check_acme_client_order_dns`.

- [ ] **Step 1: Add the response DTO**

In `backend/src/acme_client/types.rs`, add after `CreateOrderResponse` (before the `#[cfg(test)]` block):

```rust
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DnsCheckResponse {
    pub ok: bool,
    pub expected: Vec<String>,
    pub found: Vec<String>,
    pub missing: Vec<String>,
    pub error: Option<String>,
}
```

- [ ] **Step 2: Add the route handler**

In `backend/src/acme_client/routes.rs`, extend the `use crate::acme_client::types::{…}` import to also include `DnsCheckResponse`. Then add this handler immediately after `issue_acme_client_order` (before `delete_acme_client_order`):

```rust
#[openapi(tag = "ACME Client")]
#[post("/acme-client/orders/<id>/check-dns")]
pub async fn check_acme_client_order_dns(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
) -> Result<Json<DnsCheckResponse>, ApiError> {
    let order = state.db.get_acme_client_order(id).await?;
    let resolver_addr = state.settings.get_acme_dns_resolver();
    let accept_invalid_certs = state.settings.get_acme_accept_invalid_certs();

    // Resolver-only visibility check. Never contacts the CA and never mutates order status.
    match client::check_txt_records(&order.domain, &order.txt_records, &resolver_addr, accept_invalid_certs).await {
        Ok(outcome) => Ok(Json(DnsCheckResponse {
            ok: outcome.ok,
            expected: outcome.expected,
            found: outcome.found,
            missing: outcome.missing,
            error: None,
        })),
        // A lookup failure is surfaced in-band (200 + error) so the UI can render the reason
        // in the modal instead of showing a generic 500.
        Err(e) => Ok(Json(DnsCheckResponse {
            ok: false,
            expected: order.txt_records.iter().map(|r| r.value.clone()).collect(),
            found: vec![],
            missing: order.txt_records.iter().map(|r| r.value.clone()).collect(),
            error: Some(e.to_string()),
        })),
    }
}
```

- [ ] **Step 3: Register the route in all three mount lists**

In `backend/src/lib.rs`, add `check_acme_client_order_dns,` on its own line immediately after each of the three `issue_acme_client_order,` entries (there are exactly three, one per `openapi_get_routes!` block).

- [ ] **Step 4: Build to verify it compiles**

Run: `cd backend && cargo build 2>&1 | tail -8`
Expected: `Finished` with zero warnings. (If `check_acme_client_order_dns` is reported as unused, a mount list entry was missed — add it.)

- [ ] **Step 5: Commit**

```bash
git add backend/src/acme_client/types.rs backend/src/acme_client/routes.rs backend/src/lib.rs
git commit -m "feat(acme-client): check-dns endpoint (resolver-only, no CA contact)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Frontend type + API method + store action

**Files:**
- Modify: `frontend/src/types/AcmeClient.ts` (add `DnsCheckResult`)
- Modify: `frontend/src/api/acmeClient.ts` (add `checkDns`)
- Modify: `frontend/src/stores/acmeClient.ts` (add `checkDns` action)

**Interfaces:**
- Produces:
  - Type `DnsCheckResult { ok: boolean; expected: string[]; found: string[]; missing: string[]; error: string | null }`
  - `api.checkDns(id: number): Promise<DnsCheckResult>`
  - store action `checkDns(id: number): Promise<DnsCheckResult>`

- [ ] **Step 1: Add the type**

In `frontend/src/types/AcmeClient.ts`, add:

```ts
export interface DnsCheckResult {
  ok: boolean
  expected: string[]
  found: string[]
  missing: string[]
  error: string | null
}
```

- [ ] **Step 2: Add the API method**

In `frontend/src/api/acmeClient.ts`, add `DnsCheckResult` to the type import block, then add after `issueOrder`:

```ts
export const checkDns = async (id: number): Promise<DnsCheckResult> =>
    ApiClient.post<DnsCheckResult>(`/acme-client/orders/${id}/check-dns`, {})
```

- [ ] **Step 3: Add the store action**

In `frontend/src/stores/acmeClient.ts`, add this action right after the `issue` action (mirroring its axios error handling; it does NOT toggle `this.loading` so it never blocks the issue button's spinner). Ensure `DnsCheckResult` is importable — if the store imports types from `@/types/AcmeClient`, add it there:

```ts
        async checkDns(id: number): Promise<DnsCheckResult> {
            this.error = null
            try {
                return await api.checkDns(id)
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to check DNS: ' + (err.response?.data?.error ?? 'Unknown error')
                } else {
                    this.error = 'Failed to check DNS'
                }
                console.error(err)
                throw err
            }
        },
```

- [ ] **Step 4: Type-check**

Run: `cd frontend && npx vue-tsc --noEmit 2>&1 | tail -8`
Expected: `ok` (no type errors).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/types/AcmeClient.ts frontend/src/api/acmeClient.ts frontend/src/stores/acmeClient.ts
git commit -m "feat(acme-client): frontend checkDns type, api, store action

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Frontend two-button modal (Check DNS / Start issuance)

**Files:**
- Modify: `frontend/src/components/AcmeClientTab.vue`
- Modify: `frontend/src/locales/en.json`
- Modify: `frontend/src/locales/es.json`

**Interfaces:**
- Consumes: `store.checkDns` (Task 4), `store.issue`, `DnsCheckResult` type, `BaseModal` `#footer` slot (already supported: slot name `footer`, and `submitLabel`/`@submit` become unused for this modal).

- [ ] **Step 1: Add i18n keys (EN)**

In `frontend/src/locales/en.json`, inside the `le` object, insert these keys immediately after the existing `"dnsTiming"` line:

```json
    "checkDns": "Check DNS",
    "startIssue": "Start issuance",
    "dnsChecking": "Checking DNS…",
    "dnsOk": "Both records are visible in DNS — you can start issuance.",
    "dnsMissingSome": "Still missing from DNS:",
    "dnsFoundNone": "No TXT records are published at this name yet.",
    "dnsPublished": "Currently published:",
```

- [ ] **Step 2: Add i18n keys (ES)**

In `frontend/src/locales/es.json`, inside the `le` object after the existing `"dnsTiming"` line add:

```json
    "checkDns": "Comprobar DNS",
    "startIssue": "Iniciar emisión",
    "dnsChecking": "Comprobando DNS…",
    "dnsOk": "Ambos registros son visibles en DNS: ya puedes iniciar la emisión.",
    "dnsMissingSome": "Aún faltan en DNS:",
    "dnsFoundNone": "Todavía no hay registros TXT publicados en este nombre.",
    "dnsPublished": "Publicados actualmente:",
```

- [ ] **Step 3: Add ephemeral state + handlers in the component script**

In `frontend/src/components/AcmeClientTab.vue`, in the `<script setup>` TXT-records section (near `const currentTxtRecords`), add the `DnsCheckResult` import to the existing `import type { … } from '@/types/AcmeClient'` line, then add:

```ts
const dnsChecking = ref(false)
const dnsOk = ref(false)
const dnsResult = ref<DnsCheckResult | null>(null)

const resetDnsGate = () => {
  dnsChecking.value = false
  dnsOk.value = false
  dnsResult.value = null
}

const runDnsCheck = async () => {
  if (currentOrderId.value === null) return
  dnsChecking.value = true
  try {
    const r = await store.checkDns(currentOrderId.value)
    dnsResult.value = r
    dnsOk.value = r.ok
  } catch {
    dnsOk.value = false
  } finally {
    dnsChecking.value = false
  }
}
```

- [ ] **Step 4: Reset the gate wherever the modal opens/closes**

In the same file, add `resetDnsGate()` as the first line inside `openExistingTxtModal`, inside `closeTxtModal`, and in `submitNewOrder` right before `isTxtVisible.value = true`. Example for `openExistingTxtModal`:

```ts
const openExistingTxtModal = (order: AcmeClientOrder) => {
  resetDnsGate()
  store.error = null
  currentOrderId.value = order.id
  currentTxtRecords.value = order.txt_records ?? []
  isTxtVisible.value = true
}
```

- [ ] **Step 5: Replace the modal footer with two buttons + result display**

In the TXT Records `BaseModal` template, (a) remove the `:submitLabel` / `:submitIcon` / `:submitDisabled` / `:loading` / `@submit` props usage by supplying a custom footer, and (b) render the check result. Change the modal opening tag to keep `v-model:visible`, `:title`, `@cancel="closeTxtModal"`, `width="620px"`, and add the footer slot. Concretely, replace the `<BaseModal … @submit="checkAndIssue" …>` opening tag's submit-related bindings so it reads:

```vue
    <BaseModal
      v-model:visible="isTxtVisible"
      :title="$t('le.txtRecords')"
      @cancel="closeTxtModal"
      width="620px"
    >
```

Then, immediately after the existing `<div v-if="store.error" class="vt-error">{{ store.error }}</div>` line, add the result block:

```vue
        <div v-if="dnsResult && dnsResult.ok" class="vt-success">
          <i class="pi pi-check-circle" /> {{ $t('le.dnsOk') }}
        </div>
        <div v-else-if="dnsResult && !dnsResult.error" class="vt-error">
          <template v-if="dnsResult.found.length">
            {{ $t('le.dnsPublished') }} {{ dnsResult.found.join(', ') }}
          </template>
          <template v-else>{{ $t('le.dnsFoundNone') }}</template>
          <br />
          {{ $t('le.dnsMissingSome') }} {{ dnsResult.missing.join(', ') }}
        </div>
```

Finally, add the footer slot just before `</BaseModal>` (after the closing `</div>` of `vt-form`):

```vue
      <template #footer>
        <Button
          :label="$t('common.cancel')"
          severity="secondary"
          text
          @click="closeTxtModal"
        />
        <Button
          :label="dnsChecking ? $t('le.dnsChecking') : $t('le.checkDns')"
          icon="pi pi-search"
          severity="secondary"
          outlined
          :loading="dnsChecking"
          @click="runDnsCheck"
        />
        <Button
          :label="store.loading ? $t('common.creating') : $t('le.startIssue')"
          icon="pi pi-check"
          :disabled="!dnsOk || store.loading"
          :loading="store.loading"
          @click="checkAndIssue"
        />
      </template>
```

(`Button` is already imported in this component.)

- [ ] **Step 6: Add `.vt-success` style**

In the same file's `<style scoped>`, add next to `.vt-error`:

```css
.vt-success {
  background: color-mix(in srgb, #22c55e 22%, transparent);
  color: #eafff1;
  padding: 8px 12px;
  border-radius: 6px;
  margin-bottom: 12px;
  font-size: 13px;
}

.vt-success .pi {
  margin-right: 6px;
}
```

- [ ] **Step 7: Type-check the frontend**

Run: `cd frontend && npx vue-tsc --noEmit 2>&1 | tail -8`
Expected: `ok`.

- [ ] **Step 8: Verify JSON locales parse**

Run: `cd frontend && node -e "JSON.parse(require('fs').readFileSync('src/locales/en.json','utf8'));JSON.parse(require('fs').readFileSync('src/locales/es.json','utf8'));console.log('json ok')"`
Expected: `json ok`.

- [ ] **Step 9: Commit**

```bash
git add frontend/src/components/AcmeClientTab.vue frontend/src/locales/en.json frontend/src/locales/es.json
git commit -m "feat(acme-client): split TXT modal into Check DNS + gated Start issuance

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Manual verification (after all tasks)

1. `cd backend && cargo build && cargo test --lib acme_client` → green.
2. `cd frontend && npx vue-tsc --noEmit` → `ok`.
3. Run the app; open ACME Client tab → create/open an order → modal shows two buttons.
4. "Start issuance" is disabled initially. Click "Check DNS":
   - Records missing → red block lists published vs missing; issue stays disabled.
   - Records present → green "both visible" block; issue button enables.
5. Click "Start issuance" → existing issue flow runs. On CA rejection, the detailed
   `order_validation_error` message shows (unchanged behavior).
6. Close and reopen the modal → gate resets (issue disabled until re-check).

## Notes on scope / compatibility

- `issue` endpoint and its CA-rejection messaging are unchanged in behavior; only the
  precheck internals were refactored to share `check_txt_records`.
- No DB migration; gate is purely client-side.
- The check endpoint is additive; existing API consumers are unaffected.
