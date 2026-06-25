# Linear-like Frontend Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Bootstrap UI with a Linear-like PrimeVue 4 interface — dark/light/auto themes, a collapsible cookie-persisted sidebar, all 7 screens refactored, plus two new import dialogs wiring the Phase 1 backend.

**Architecture:** View layer only. PrimeVue 4 components with a custom Aura-based preset mapped to Linear design tokens; Tailwind as a utility layer. `stores/`, `api/`, router, and domain types are untouched — components keep their existing store calls and props. Foundation lands first (theme, layout, sidebar, reference screen Certificates), then remaining screens follow the established pattern.

**Tech Stack:** Vue 3.5 + TS 6 + Vite 8 + Pinia + vue-router 5 + vue-i18n 11. Add: PrimeVue 4, @primeuix/themes, primeicons, Tailwind 3.4, tailwindcss-primeui. Tests: vitest + @vue/test-utils + jsdom (unit), Playwright (E2E, already installed).

## Global Constraints

- Do NOT modify `src/stores/*`, `src/api/*`, `src/router/router.ts` routes, or `src/types/*` (logic is stable). Components keep their existing store/api calls.
- Theme is toggled by class `dark` on `<html>` (PrimeVue `darkModeSelector: '.dark'`, Tailwind `darkMode: 'class'`). Default = dark. Auto follows `prefers-color-scheme`. Persist key: `localStorage 'theme'` (existing).
- Sidebar collapse state persists in cookie `vaultls_sidebar` with values `expanded|collapsed`, read synchronously at init.
- Primary accent `#6e56cf`. Dark surfaces: bg `#0b0d12`, surface `#0e1016`, card `#11131a`, border `rgba(255,255,255,.06)`, text `#e6e8ee`, muted `#9ca3b4`. Light: bg `#f8f8f7`, surface/card `#ffffff`, border `#ececec`, text `#18181b`, muted `#71717a`. Status ok/warn/err dark `#4ade80`/`#fbbf24`/`#f87171`, light `#16a34a`/`#d97706`/`#dc2626`.
- All commands run from `frontend/`. Unit: `npm run test:unit`. Build/type-check: `npm run build`.
- When configuring PrimeVue 4 / Tailwind / @primeuix/themes, verify current API via Context7 MCP before writing config (versions move fast).
- Commit after each task. Branch: `feat/frontend-redesign`.

---

## File Structure

- Modify: `frontend/package.json` (deps, scripts), `frontend/vite.config.ts`, create `frontend/tailwind.config.ts`, `frontend/postcss.config.js`, `frontend/vitest.config.ts`
- Modify: `frontend/src/main.ts` (remove Bootstrap, add PrimeVue + CSS)
- Create: `frontend/src/assets/theme.css` (design tokens), `frontend/src/assets/tailwind.css`
- Create: `frontend/src/theme/preset.ts` (PrimeVue preset)
- Rewrite: `frontend/src/stores/theme.ts` (class `dark` instead of `data-bs-theme`) — *exception to the no-stores rule: this store drives theming, explicitly in scope*
- Create: `frontend/src/composables/useSidebar.ts`
- Rewrite: `frontend/src/layouts/MainLayout.vue` → `AppLayout`, `frontend/src/components/Sidebar.vue` → `AppSidebar.vue`
- Rewrite (view layer): `OverviewTab.vue`, `CATab.vue`, `AcmeTab.vue`, `SettingsTab.vue`, `UserTab.vue`, `views/LoginView.vue`, `views/FirstSetupView.vue`
- Create: `frontend/src/components/dialogs/ImportCertificateDialog.vue`, `frontend/src/components/dialogs/ImportCaDialog.vue`
- Modify: `frontend/src/api/certificates.ts`, `frontend/src/api/cas.ts` (import methods), `frontend/src/stores/certificates.ts`, `frontend/src/stores/cas.ts` (import actions) — *exception: thin additive methods for new endpoints, no logic change to existing*
- Modify: i18n locale files under `frontend/src/plugins/` or locale dir (add keys)

---

## Task 0: Foundation — PrimeVue + Tailwind + theme tokens

**Files:**
- Modify: `frontend/package.json`, `frontend/vite.config.ts`, `frontend/src/main.ts`
- Create: `frontend/postcss.config.js`, `frontend/tailwind.config.ts`, `frontend/vitest.config.ts`, `frontend/src/assets/tailwind.css`, `frontend/src/assets/theme.css`, `frontend/src/theme/preset.ts`
- Rewrite: `frontend/src/stores/theme.ts`
- Test: `frontend/src/stores/theme.spec.ts`

**Interfaces:**
- Produces: PrimeVue registered globally; `useThemeStore` with `theme: Ref<'light'|'dark'|'auto'>`, `setTheme(t)`, `applyTheme()` that toggles class `dark` on `document.documentElement`.
- Produces: design tokens as CSS variables (see Global Constraints) in `theme.css`.

- [ ] **Step 1: Install dependencies**

```bash
cd frontend
npm install primevue@^4 @primeuix/themes primeicons
npm install -D tailwindcss@^3.4 postcss autoprefixer tailwindcss-primeui vitest @vue/test-utils jsdom
npm uninstall bootstrap
```

- [ ] **Step 2: Add test script** to `frontend/package.json` `scripts`:

```json
"test:unit": "vitest run",
"test:watch": "vitest"
```

- [ ] **Step 3: Create `frontend/vitest.config.ts`**

```ts
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  plugins: [vue()],
  test: { environment: 'jsdom', globals: true },
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
})
```

- [ ] **Step 4: Create `frontend/postcss.config.js` and `frontend/tailwind.config.ts`**

`postcss.config.js`:
```js
export default { plugins: { tailwindcss: {}, autoprefixer: {} } }
```
`tailwind.config.ts`:
```ts
import type { Config } from 'tailwindcss'
import primeui from 'tailwindcss-primeui'
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{vue,ts}'],
  plugins: [primeui],
} satisfies Config
```

- [ ] **Step 5: Create token + tailwind CSS**

`frontend/src/assets/tailwind.css`:
```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```
`frontend/src/assets/theme.css` — define both palettes (values from Global Constraints):
```css
:root {
  --vt-bg:#f8f8f7; --vt-surface:#fff; --vt-card:#fff; --vt-border:#ececec;
  --vt-text:#18181b; --vt-muted:#71717a; --vt-primary:#6e56cf;
  --vt-ok:#16a34a; --vt-warn:#d97706; --vt-err:#dc2626;
}
:root.dark {
  --vt-bg:#0b0d12; --vt-surface:#0e1016; --vt-card:#11131a; --vt-border:rgba(255,255,255,.06);
  --vt-text:#e6e8ee; --vt-muted:#9ca3b4; --vt-primary:#6e56cf;
  --vt-ok:#4ade80; --vt-warn:#fbbf24; --vt-err:#f87171;
}
body { background:var(--vt-bg); color:var(--vt-text); }
```

- [ ] **Step 6: Create PrimeVue preset `frontend/src/theme/preset.ts`**

```ts
import { definePreset } from '@primeuix/themes'
import Aura from '@primeuix/themes/aura'

// Linear-like preset: violet primary, surfaces mapped to our tokens.
export const VaulTLSPreset = definePreset(Aura, {
  semantic: {
    primary: {
      50:'#f2effb',100:'#e3dcf7',200:'#c8baef',300:'#ac97e6',400:'#9175de',
      500:'#6e56cf',600:'#5d47b8',700:'#4c3a97',800:'#3a2d74',900:'#2a2154',950:'#1a1436',
    },
    colorScheme: {
      dark: {
        surface: { 0:'#ffffff', 50:'#e6e8ee', 100:'#cbd0db', 200:'#9ca3b4',
          300:'#7c8190', 400:'#5b606e', 500:'#3a3f4b', 600:'#272b34',
          700:'#181b22', 800:'#11131a', 900:'#0e1016', 950:'#0b0d12' },
      },
    },
  },
})
```

- [ ] **Step 7: Rewrite `frontend/src/main.ts`**

```ts
import './assets/tailwind.css'
import './assets/theme.css'
import 'primeicons/primeicons.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'
import router from './router/router'
import { i18n } from './plugins/i18n'
import { VaulTLSPreset } from './theme/preset'
import App from './App.vue'
import { useSetupStore } from '@/stores/setup.ts'
import { useAuthStore } from '@/stores/auth.ts'

async function initApp() {
  const pinia = createPinia()
  const app = createApp(App)
  app.use(pinia)
  app.use(i18n)
  app.use(PrimeVue, { theme: { preset: VaulTLSPreset, options: { darkModeSelector: '.dark' } } })
  app.use(ToastService)

  const setupStore = useSetupStore()
  await setupStore.init()
  const authStore = useAuthStore()
  await authStore.init()

  app.use(router)
  app.mount('#app')
}
initApp().catch((err) => console.error('Failed to initialize app:', err))
```

- [ ] **Step 8: Write failing test `frontend/src/stores/theme.spec.ts`**

```ts
import { setActivePinia, createPinia } from 'pinia'
import { beforeEach, describe, expect, it } from 'vitest'
import { useThemeStore } from '@/stores/theme'

describe('theme store', () => {
  beforeEach(() => { setActivePinia(createPinia()); document.documentElement.className = '' })

  it('applies dark by adding class "dark"', () => {
    const s = useThemeStore()
    s.setTheme('dark'); s.applyTheme()
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })

  it('applies light by removing class "dark"', () => {
    const s = useThemeStore()
    s.setTheme('light'); s.applyTheme()
    expect(document.documentElement.classList.contains('dark')).toBe(false)
  })
})
```

- [ ] **Step 9: Run test, verify it fails** — `npm run test:unit` → fails (store still sets `data-bs-theme`).

- [ ] **Step 10: Rewrite `frontend/src/stores/theme.ts`**

```ts
import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
export type Theme = 'light' | 'dark' | 'auto'

export const useThemeStore = defineStore('theme', () => {
  const theme = ref<Theme>((localStorage.getItem('theme') as Theme) || 'dark')
  const setTheme = (t: Theme) => { theme.value = t; localStorage.setItem('theme', t) }
  const applyTheme = () => {
    const actual = theme.value === 'auto'
      ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : theme.value
    document.documentElement.classList.toggle('dark', actual === 'dark')
  }
  watch(theme, applyTheme, { immediate: true })
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (theme.value === 'auto') applyTheme()
  })
  return { theme, setTheme, applyTheme }
})
```

- [ ] **Step 11: Run test + build, verify pass**

Run: `npm run test:unit` → PASS. Run: `npm run build` → no TS errors, no Bootstrap import remains.

- [ ] **Step 12: Commit**

```bash
git add frontend/
git commit -m "feat(ui): foundation — PrimeVue 4 + Tailwind + Linear theme tokens"
```

---

## Task 1: `useSidebar` composable (cookie persistence)

**Files:**
- Create: `frontend/src/composables/useSidebar.ts`
- Test: `frontend/src/composables/useSidebar.spec.ts`

**Interfaces:**
- Produces: `useSidebar()` returning `{ collapsed: Ref<boolean>, toggle(): void }`. Reads cookie `vaultls_sidebar` synchronously at module init; `toggle` writes it.

- [ ] **Step 1: Write failing test `useSidebar.spec.ts`**

```ts
import { beforeEach, describe, expect, it } from 'vitest'
import { useSidebar } from '@/composables/useSidebar'

describe('useSidebar', () => {
  beforeEach(() => { document.cookie = 'vaultls_sidebar=; max-age=0' })

  it('defaults to expanded when no cookie', () => {
    const { collapsed } = useSidebar()
    expect(collapsed.value).toBe(false)
  })

  it('toggle flips state and writes cookie', () => {
    const { collapsed, toggle } = useSidebar()
    toggle()
    expect(collapsed.value).toBe(true)
    expect(document.cookie).toContain('vaultls_sidebar=collapsed')
  })

  it('reads collapsed cookie at init', () => {
    document.cookie = 'vaultls_sidebar=collapsed'
    const { collapsed } = useSidebar()
    expect(collapsed.value).toBe(true)
  })
})
```

- [ ] **Step 2: Run, verify fail** — `npm run test:unit useSidebar` → module not found.

- [ ] **Step 3: Implement `frontend/src/composables/useSidebar.ts`**

```ts
import { ref } from 'vue'

const COOKIE = 'vaultls_sidebar'
function readCookie(): boolean {
  const m = document.cookie.match(new RegExp('(?:^|; )' + COOKIE + '=([^;]+)'))
  return m?.[1] === 'collapsed'
}
const collapsed = ref<boolean>(readCookie())

export function useSidebar() {
  const toggle = () => {
    collapsed.value = !collapsed.value
    document.cookie = `${COOKIE}=${collapsed.value ? 'collapsed' : 'expanded'}; path=/; max-age=31536000`
  }
  return { collapsed, toggle }
}
```

- [ ] **Step 4: Run, verify pass** — `npm run test:unit useSidebar` → 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/composables
git commit -m "feat(ui): useSidebar composable with cookie persistence"
```

---

## Task 2: AppLayout + AppSidebar (collapsible, reference navigation)

**Files:**
- Rewrite: `frontend/src/layouts/MainLayout.vue`
- Rewrite: `frontend/src/components/Sidebar.vue` → rename to `frontend/src/components/AppSidebar.vue` (update import in MainLayout)
- Modify: `frontend/src/router/router.ts` (only the `MainLayout` import path stays; if renaming layout file, keep filename `MainLayout.vue` to avoid touching router — recommended)

**Interfaces:**
- Consumes: `useSidebar()` (Task 1), `useThemeStore` (Task 0), existing `useAuthStore` (`isAdmin`), `ProfileCard.vue`.
- Produces: shell layout with collapsible sidebar; content area renders `<router-view/>`.

- [ ] **Step 1: Rewrite `frontend/src/components/Sidebar.vue`** (keep filename) as the Linear sidebar

Read the current `Sidebar.vue` first to preserve nav items (Overview, CA, ACME, Users, Settings) and admin-only visibility (`authStore.isAdmin` gates Users/ACME/Settings — confirm against current file). Replace markup with:

```vue
<template>
  <aside :class="['vt-sidebar', { collapsed }]">
    <div class="vt-brand"><span class="vt-logo">🔐</span><span v-if="!collapsed">VaulTLS</span></div>
    <nav class="vt-nav">
      <RouterLink v-for="item in items" :key="item.name" :to="item.to" class="vt-nav-item"
        v-tooltip.right="collapsed ? $t(item.label) : ''">
        <i :class="item.icon" /><span v-if="!collapsed">{{ $t(item.label) }}</span>
      </RouterLink>
    </nav>
    <div class="vt-foot">
      <button class="vt-collapse" @click="toggle"><i :class="collapsed ? 'pi pi-angle-right' : 'pi pi-angle-left'" /></button>
      <ProfileCard v-if="!collapsed" />
    </div>
  </aside>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import Tooltip from 'primevue/tooltip'
import ProfileCard from '@/components/ProfileCard.vue'
import { useSidebar } from '@/composables/useSidebar'
import { useAuthStore } from '@/stores/auth'

const vTooltip = Tooltip
const { collapsed, toggle } = useSidebar()
const auth = useAuthStore()
const items = computed(() => [
  { name: 'overview', to: '/overview', icon: 'pi pi-shield', label: 'nav.certificates' },
  { name: 'ca', to: '/ca', icon: 'pi pi-building-columns', label: 'nav.cas' },
  ...(auth.isAdmin ? [
    { name: 'acme', to: '/acme', icon: 'pi pi-bolt', label: 'nav.acme' },
    { name: 'users', to: '/users', icon: 'pi pi-users', label: 'nav.users' },
    { name: 'settings', to: '/settings', icon: 'pi pi-cog', label: 'nav.settings' },
  ] : []),
])
</script>

<style scoped>
.vt-sidebar{width:240px;background:var(--vt-surface);border-right:1px solid var(--vt-border);
  display:flex;flex-direction:column;height:100vh;position:fixed;transition:width .2s;padding:14px 10px;}
.vt-sidebar.collapsed{width:64px;}
.vt-brand{display:flex;align-items:center;gap:10px;font-weight:700;padding:8px 8px 18px;}
.vt-nav{display:flex;flex-direction:column;gap:4px;}
.vt-nav-item{display:flex;align-items:center;gap:12px;padding:9px 11px;border-radius:9px;
  color:var(--vt-muted);text-decoration:none;font-size:14px;font-weight:500;}
.vt-nav-item:hover{background:rgba(127,127,127,.08);color:var(--vt-text);}
.vt-nav-item.router-link-active{background:color-mix(in srgb,var(--vt-primary) 16%,transparent);color:var(--vt-primary);}
.vt-foot{margin-top:auto;display:flex;flex-direction:column;gap:8px;}
.vt-collapse{background:transparent;border:1px solid var(--vt-border);border-radius:8px;
  color:var(--vt-muted);padding:6px;cursor:pointer;}
</style>
```

- [ ] **Step 2: Rewrite `frontend/src/layouts/MainLayout.vue`** (keep filename — router unchanged)

```vue
<template>
  <div class="vt-app">
    <Sidebar />
    <main :class="['vt-content', { collapsed }]"><router-view /></main>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import Sidebar from '@/components/Sidebar.vue'
import { useSidebar } from '@/composables/useSidebar'
import { useAuthStore } from '@/stores/auth'
import { useSettingsStore } from '@/stores/settings'

const { collapsed } = useSidebar()
const auth = useAuthStore(); const settings = useSettingsStore()
onMounted(async () => { if (auth.isAdmin) await settings.fetchSettings() })
</script>

<style scoped>
.vt-app{display:flex;min-height:100vh;}
.vt-content{margin-left:240px;flex:1;padding:28px 36px;transition:margin-left .2s;}
.vt-content.collapsed{margin-left:64px;}
</style>
```

- [ ] **Step 3: Verify build + manual smoke**

Run: `npm run build` → no TS errors. Run `npm run dev`, confirm sidebar renders, collapses on button click, and stays collapsed after reload (cookie). If `ProfileCard.vue` references Bootstrap classes, leave for its own screen task — only ensure it imports.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/layouts frontend/src/components/Sidebar.vue
git commit -m "feat(ui): collapsible Linear sidebar + app layout"
```

---

## Task 3: CertificatesView — reference screen (OverviewTab)

**Files:**
- Rewrite: `frontend/src/components/OverviewTab.vue`
- Test: Playwright smoke (added in Task 11); build type-check here.

**Interfaces:**
- Consumes: existing `useCertificatesStore` (read its current API by reading the file — do NOT change the store). PrimeVue `DataTable`, `Column`, `Tag`, `Button`, `InputText`.
- Produces: the canonical screen pattern (header + actions + DataTable + status tags) that Tasks 6–10 follow.

> This is the reference screen. Read the current `OverviewTab.vue` fully first to map every store call, prop, computed, and action (create cert, download, revoke, delete, password reveal). Reproduce ALL existing behavior; only the presentation changes.

- [ ] **Step 1: Rewrite `OverviewTab.vue` presentation** using this structure (fill data bindings from the existing store):

```vue
<template>
  <div>
    <header class="vt-head">
      <div><h1>{{ $t('nav.certificates') }}</h1><p class="vt-sub">{{ $t('certs.subtitle') }}</p></div>
      <div class="vt-actions">
        <Button :label="$t('certs.import')" icon="pi pi-upload" severity="secondary" outlined @click="showImport = true" />
        <Button :label="$t('certs.create')" icon="pi pi-plus" @click="/* existing create handler */" />
      </div>
    </header>

    <DataTable :value="certificates" dataKey="id" :globalFilterFields="['name','ca','serial']"
      v-model:filters="filters" filterDisplay="menu" removableSort class="vt-table">
      <template #header>
        <span class="p-input-icon-left"><i class="pi pi-search" />
          <InputText v-model="filters['global'].value" :placeholder="$t('common.search')" /></span>
      </template>
      <Column field="name" :header="$t('certs.cn')" sortable />
      <Column field="type" :header="$t('certs.type')" />
      <Column field="ca" :header="$t('certs.ca')" />
      <Column field="valid_until" :header="$t('certs.validUntil')" sortable />
      <Column :header="$t('certs.status')">
        <template #body="{ data }">
          <Tag :severity="statusSeverity(data)" :value="statusLabel(data)" />
        </template>
      </Column>
      <Column>
        <template #body="{ data }"><!-- existing row actions: download/revoke/delete --></template>
      </Column>
    </DataTable>

    <ImportCertificateDialog v-model:visible="showImport" @imported="/* refresh from store */" />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { FilterMatchMode } from '@primevue/core/api'
import ImportCertificateDialog from '@/components/dialogs/ImportCertificateDialog.vue'
// import + use the EXISTING certificates store exactly as the current file does

const showImport = ref(false)
const filters = ref({ global: { value: null, matchMode: FilterMatchMode.CONTAINS } })
// statusSeverity(data) -> 'success'|'warn'|'danger'; statusLabel(data) -> i18n string
// Reuse the existing computed list, create/revoke/delete/download handlers verbatim.
</script>

<style scoped>
.vt-head{display:flex;align-items:flex-start;margin-bottom:22px;}
.vt-head h1{font-size:22px;font-weight:700;}
.vt-sub{font-size:13px;color:var(--vt-muted);margin-top:3px;}
.vt-actions{margin-left:auto;display:flex;gap:10px;}
</style>
```

- [ ] **Step 2: Map all existing behavior** — ensure create/revoke/delete/download/password actions call the same store methods as before. Remove Bootstrap markup/classes from this file.

- [ ] **Step 3: Verify** — `npm run build` passes; `npm run dev` shows the certificates table with data, search filters, status tags themed.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/OverviewTab.vue
git commit -m "feat(ui): CertificatesView reference screen (PrimeVue DataTable)"
```

---

## Task 4: ImportCertificateDialog + api/store wiring

**Files:**
- Create: `frontend/src/components/dialogs/ImportCertificateDialog.vue`
- Modify: `frontend/src/api/certificates.ts`, `frontend/src/stores/certificates.ts`
- Test: `frontend/src/components/dialogs/importCert.validate.spec.ts`

**Interfaces:**
- Consumes: backend `POST /certificates/import` multipart form (verify field names in `backend/src/api.rs` `ImportCertForm`: `p12`,`password`,`cert`,`key`,`chain`,`user_id`,`ca_id`,`cert_type`,`renew_method`).
- Produces: `validateImportInput(state)` pure fn (exported from a sibling `importCert.ts`) + dialog component emitting `imported`.

- [ ] **Step 1: Write failing test for validation logic `importCert.validate.spec.ts`**

```ts
import { describe, expect, it } from 'vitest'
import { validateImportInput } from '@/components/dialogs/importCert'

describe('validateImportInput', () => {
  it('requires user_id', () => {
    expect(validateImportInput({ mode: 'p12', p12: new File([], 'a.p12'), userId: null }))
      .toContain('user_id')
  })
  it('p12 mode requires a p12 file', () => {
    expect(validateImportInput({ mode: 'p12', p12: null, userId: 1 })).toContain('p12')
  })
  it('certkey mode requires cert and key', () => {
    expect(validateImportInput({ mode: 'certkey', cert: new File([], 'c'), key: null, userId: 1 }))
      .toContain('key')
  })
  it('valid p12 input returns no errors', () => {
    expect(validateImportInput({ mode: 'p12', p12: new File([], 'a.p12'), userId: 1 })).toHaveLength(0)
  })
})
```

- [ ] **Step 2: Run, verify fail** — `npm run test:unit importCert` → module missing.

- [ ] **Step 3: Implement `frontend/src/components/dialogs/importCert.ts`**

```ts
export type ImportInput = {
  mode: 'p12' | 'certkey'
  userId: number | null
  p12?: File | null
  cert?: File | null
  key?: File | null
}
export function validateImportInput(i: ImportInput): string[] {
  const e: string[] = []
  if (i.userId == null) e.push('user_id is required')
  if (i.mode === 'p12' && !i.p12) e.push('p12 file is required')
  if (i.mode === 'certkey') {
    if (!i.cert) e.push('cert file is required')
    if (!i.key) e.push('key file is required')
  }
  return e
}
```

- [ ] **Step 4: Run, verify pass** — `npm run test:unit importCert` → 4 PASS.

- [ ] **Step 5: Add api method** in `frontend/src/api/certificates.ts` (match the file's existing axios client style; read it first):

```ts
export async function importCertificate(form: FormData): Promise<void> {
  await apiClient.post('/certificates/import', form, { headers: { 'Content-Type': 'multipart/form-data' } })
}
```
Add a thin store action `importCertificate(form)` in `frontend/src/stores/certificates.ts` that calls it and refreshes the list using the store's existing fetch action.

- [ ] **Step 6: Implement dialog `ImportCertificateDialog.vue`**

PrimeVue `Dialog` + `FileUpload` (mode select p12 / cert+key via `SelectButton`), `InputText` password, user/CA selectors (PrimeVue `Select` fed by existing users/cas stores), submit builds `FormData` with the exact backend field names, calls store action, shows PrimeVue `Toast` on server error, emits `imported` on success. Use `validateImportInput` before submit. Props: `visible` (v-model). Keep it under ~150 lines; extract no business logic beyond `importCert.ts`.

- [ ] **Step 7: Verify** — `npm run test:unit` all pass; `npm run build` passes.

- [ ] **Step 8: Commit**

```bash
git add frontend/src/components/dialogs frontend/src/api/certificates.ts frontend/src/stores/certificates.ts
git commit -m "feat(ui): ImportCertificateDialog wired to POST /certificates/import"
```

---

## Task 5: ImportCaDialog + api/store wiring

**Files:**
- Create: `frontend/src/components/dialogs/ImportCaDialog.vue`
- Modify: `frontend/src/api/cas.ts`, `frontend/src/stores/cas.ts`

**Interfaces:**
- Consumes: backend `POST /certificates/ca/import` form (`ImportCaForm`: `ca_cert`, optional `ca_key`, optional `name`).
- Produces: dialog emitting `imported`.

- [ ] **Step 1: Add api method** in `frontend/src/api/cas.ts`:

```ts
export async function importCa(form: FormData): Promise<number> {
  const { data } = await apiClient.post('/certificates/ca/import', form, { headers: { 'Content-Type': 'multipart/form-data' } })
  return data
}
```
Add a thin `importCa(form)` action in `frontend/src/stores/cas.ts` that calls it and refreshes the CA list.

- [ ] **Step 2: Implement `ImportCaDialog.vue`**

PrimeVue `Dialog` + `FileUpload` for `ca_cert` (required) and optional `ca_key`, optional `name` `InputText`. Submit builds `FormData` (`ca_cert`, `ca_key`, `name`), calls store action, `Toast` on error, emits `imported`. Props `visible` v-model. No new business logic.

- [ ] **Step 3: Wire into CAsView trigger** — the "Import CA" button lands in Task 6; here just ensure the dialog builds standalone.

- [ ] **Step 4: Verify + Commit**

Run: `npm run build` passes.
```bash
git add frontend/src/components/dialogs/ImportCaDialog.vue frontend/src/api/cas.ts frontend/src/stores/cas.ts
git commit -m "feat(ui): ImportCaDialog wired to POST /certificates/ca/import"
```

---

## Tasks 6–10: Remaining screens (follow Task 3 pattern)

Each task: read the current component fully, reproduce ALL behavior (store calls, props, actions, admin gating), replace Bootstrap markup with PrimeVue + tokens following the Task 3 reference, remove Bootstrap classes, `npm run build`, manual smoke, commit. No business-logic changes.

### Task 6: CAsView (`CATab.vue`)
- PrimeVue `DataTable` of CAs (name, type, validity, imported badge), row actions (download, CRL, delete). Header "Import CA" button opening `ImportCaDialog` (Task 5). Show `is_imported` as a `Tag`.
- Commit: `feat(ui): CAsView with import CA`

### Task 7: AcmeView (`AcmeTab.vue`)
- `DataTable` of ACME accounts/orders + `Dialog` create/edit forms (PrimeVue form inputs). Reproduce existing ACME store actions.
- Commit: `feat(ui): AcmeView`

### Task 8: SettingsView (`SettingsTab.vue`)
- PrimeVue form (`InputText`, `Select`, `ToggleSwitch`, `Fieldset` groups: mail, OIDC, password rules) bound to existing settings store. Save button calls existing action.
- Commit: `feat(ui): SettingsView`

### Task 9: UsersView (`UserTab.vue`)
- `DataTable` of users + create/edit/delete `Dialog`. Admin-only (already gated by route/store). Reproduce existing user store actions.
- Commit: `feat(ui): UsersView`

### Task 10: Auth screens (`LoginView.vue`, `FirstSetupView.vue`)
- LoginView: centered `Card` with email/password `InputText`/`Password`, OIDC button, error `Message`. Keep existing login + OIDC handlers and client-side hashing (`utils/hash.ts`).
- FirstSetupView: `Stepper` or single `Card` form bound to existing setup store.
- Commit: `feat(ui): auth screens redesign`

---

## Task 11: i18n keys, E2E smoke, final verification

**Files:**
- Modify: i18n locale files (read `frontend/src/plugins/i18n.ts` to locate them)
- Create: `frontend/tests/e2e/redesign.spec.ts` (Playwright)

- [ ] **Step 1: Add i18n keys** (ru + en) for every new key referenced across tasks: `nav.certificates`, `nav.cas`, `nav.acme`, `nav.users`, `nav.settings`, `certs.subtitle`, `certs.import`, `certs.create`, `certs.cn`, `certs.type`, `certs.ca`, `certs.validUntil`, `certs.status`, `common.search`, plus import-dialog labels. Verify no missing-key warnings in `npm run dev` console.

- [ ] **Step 2: Write Playwright smoke `frontend/tests/e2e/redesign.spec.ts`**

Cover: login → certificates list visible; open Import Certificate dialog → fields render; toggle sidebar → reload → still collapsed (cookie); switch theme dark↔light → `html.dark` toggles. Use the project's existing Playwright config patterns. Per project rule, E2E runs against the PROD URL via `playwright-cli`.

- [ ] **Step 3: Full verification**

Run: `npm run test:unit` → all unit pass. Run: `npm run build` → no TS errors, no Bootstrap references anywhere (`grep -r bootstrap frontend/src` returns nothing).

- [ ] **Step 4: Commit**

```bash
git add frontend/
git commit -m "feat(ui): i18n keys + E2E smoke + final redesign verification"
```

---

## Self-Review Notes

- **Spec coverage:** tokens+PrimeVue (T0) · sidebar cookie (T1) · layout+collapsible (T2) · reference screen (T3) · import dialogs wiring Phase 1 (T4,T5) · all screens (T3,T6–T10) · i18n + tests (T11). All spec sections mapped.
- **No-stores exception:** T0 rewrites `theme.ts` and T4/T5 add thin additive methods to certificates/cas stores+api — explicitly scoped in Global Constraints; existing logic untouched.
- **UI tasks are not strict TDD:** screens verify via `npm run build` (vue-tsc) + manual/Playwright smoke; pure logic (theme, useSidebar, import validation) is unit-tested first. This is intentional for view-layer work.
- **Assumptions to verify during execution (flagged inline):** PrimeVue 4 / Tailwind / @primeuix/themes exact API (check via Context7); current store/component APIs (read each file before rewriting); backend multipart field names (`backend/src/api.rs`); i18n file locations.
