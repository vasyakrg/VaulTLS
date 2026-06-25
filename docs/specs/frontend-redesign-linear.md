# Spec: полный UX-редизайн фронта (Linear-like)

Статус: draft · Фаза 3 roadmap форка.

## Цель

Заменить устаревший Bootstrap-интерфейс на современный «Linear-like» — тёмный, плотный,
минималистичный, под технический инструмент (PKI/сертификаты). Переписывается **только слой
представления**; бизнес-логика (`stores/`, `api/`, роутинг, типы) не меняется.

## Зафиксированные решения

- **Визуальный язык:** Linear-like (тёмный плотный минимализм, фиолетовый акцент `#6e56cf`).
- **UI-стек:** PrimeVue 4 (styled, кастомный preset на базе Aura) + Tailwind как утилитарный слой
  (`tailwindcss-primeui`). Bootstrap 5 удаляется.
- **Сайдбар:** сворачиваемый 240px ↔ 64px, состояние в куке `vaultls_sidebar`.
- **Темы:** Dark (по умолчанию) / Light / Auto — поведение как сейчас, токены пересобираем.
- **Объём:** один цикл — фундамент + все 7 экранов + 2 новых import-диалога.
- Сохраняем: Vue 3 + TS + Vite + Pinia + vue-router + vue-i18n.

## Стек и зависимости

Добавить: `primevue@^4`, `@primeuix/themes` (preset Aura), `primeicons`, `tailwindcss`,
`tailwindcss-primeui`, `postcss`, `autoprefixer`. Dev: `vitest`, `@vue/test-utils`, `jsdom`.
Удалить: `bootstrap`. PrimeVue подключается в `src/main.ts` через `app.use(PrimeVue, { theme: { preset } })`.

## Дизайн-токены

Единый источник — CSS variables в `src/assets/theme.css` + PrimeVue preset override. Темы
переключаются классом на `<html>` (`.dark` / без класса = light; Auto читает `prefers-color-scheme`).
Сохраняем существующий `src/stores/theme.ts` как управляющий стор, расширяя его на классы токенов.

| Токен | Dark | Light |
|-------|------|-------|
| `--vt-bg` | `#0b0d12` | `#f8f8f7` |
| `--vt-surface` (панели/сайдбар) | `#0e1016` | `#ffffff` |
| `--vt-card` | `#11131a` | `#ffffff` |
| `--vt-border` | `rgba(255,255,255,.06)` | `#ececec` |
| `--vt-text` | `#e6e8ee` | `#18181b` |
| `--vt-muted` | `#9ca3b4` | `#71717a` |
| `--vt-primary` | `#6e56cf` | `#6e56cf` |
| статусы ok/warn/err | `#4ade80` / `#fbbf24` / `#f87171` | `#16a34a` / `#d97706` / `#dc2626` |

PrimeVue preset мапит semantic-токены (`primary`, `surface`, `content`) на эти значения, чтобы
DataTable/Dialog/Button наследовали тему без точечных переопределений.

## Layout + сворачиваемый сайдбар

- `src/layouts/MainLayout.vue` → переписать как `AppLayout` (grid: sidebar + content).
- `src/components/Sidebar.vue` → `AppSidebar.vue`: лого, nav-элементы (PrimeIcons, badge-счётчики из
  сторов), внизу профиль (`ProfileCard`) + переключатель темы. В свёрнутом виде (64px) — только иконки
  с tooltip.
- Новый composable `src/composables/useSidebar.ts`: состояние `collapsed` (ref), `toggle()`,
  персист в куке `vaultls_sidebar=expanded|collapsed`. Начальное значение читается из куки СИНХРОННО
  при инициализации (без «прыжка» при загрузке).

## Экраны (рефактор представления, 1:1 с текущими)

Каждый — замена внутренней разметки на PrimeVue-компоненты + токены; props/события/обращения к
сторам сохраняются.

| Сейчас | Новый | Ключевые PrimeVue-компоненты |
|--------|-------|------------------------------|
| `views/LoginView.vue` | тот же | InputText, Password, Button, Card |
| `views/FirstSetupView.vue` | тот же | Stepper/форма |
| `components/OverviewTab.vue` | `CertificatesView` | DataTable (фильтр, сортировка, статусы Tag), кнопки Создать/Импорт |
| `components/CATab.vue` | `CAsView` | DataTable, кнопка Импорт CA |
| `components/AcmeTab.vue` | `AcmeView` | DataTable, Dialog-формы |
| `components/SettingsTab.vue` | `SettingsView` | форма, Tabs/Fieldset |
| `components/UserTab.vue` | `UsersView` | DataTable, Dialog |

## Новое — UI под фичи Phase 1 (бэкенд готов, фронта нет)

- `src/components/dialogs/ImportCertificateDialog.vue` — FileUpload (drag-drop): p12+password **или**
  cert+key+chain; превью распарсенной цепочки (CN, issuer, срок) до подтверждения; выбор CA или
  автоопределение → `POST /certificates/import`. Добавить метод в `src/api/certificates.ts` и
  действие в `src/stores/certificates.ts`.
- `src/components/dialogs/ImportCaDialog.vue` — CA cert + опц. key → `POST /certificates/ca/import`.
  Метод в `src/api/cas.ts` + действие в `src/stores/cas.ts`.
- Серверные ошибки (битый ввод, неверная цепочка, keyless-CA) показываются через Toast.

## i18n

vue-i18n сохраняем. Добавить ключи (ru + en) для импорт-форм, тултипов свёрнутого сайдбара, новых
статусов. Существующие ключи переиспользуем.

## Тестирование

- **Unit (vitest + @vue/test-utils + jsdom):** `useSidebar` (кука читается/пишется, toggle);
  валидация формы импорта (взаимоисключение p12 ↔ cert+key; обязательность user_id).
- **E2E (Playwright, уже в зависимостях):** логин → список сертификатов → открыть ImportCertificate,
  загрузить cert+key → серт появился; сворачивание сайдбара сохраняется после перезагрузки (кука);
  переключение темы Dark/Light/Auto. По глобальному правилу проекта Web-проверки идут на PROD URL
  через `playwright-cli`.
- `npm run build` (`vue-tsc --build` + vite) — без TS-ошибок.

## Не-цели

- Не меняем бизнес-логику, контракты API, роутинг, бэкенд, типы домена.
- Не добавляем новые экраны сверх существующих (кроме 2 import-диалогов под готовый бэкенд).
- SSR/PWA вне объёма.

## Риски

- **PrimeVue 4 preset под Linear** — semantic-токены нужно выверить, чтобы DataTable/Dialog не
  «выбивались» из тёмной темы; заложить эталонную выверку на экране Сертификаты до тиражирования.
- **Tailwind + PrimeVue слои** — порядок CSS (preflight Tailwind не должен ломать PrimeVue);
  использовать `tailwindcss-primeui` и проверить reset.
- **Большой объём за один цикл** — 7 экранов + фундамент; план должен идти экранами как отдельными
  задачами, фундамент первым (эталон — Сертификаты), затем остальные по образцу.
- **FileUpload + multipart** — фронт должен слать `multipart/form-data` соответственно бэкенд-формам
  (`ImportCertForm`/`ImportCaForm`); свериться с реальными именами полей в `backend/src/api.rs`.
