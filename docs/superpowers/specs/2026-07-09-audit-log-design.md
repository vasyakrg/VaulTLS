# Audit Log — Design

**Date:** 2026-07-09
**Status:** Approved
**Scope:** Backend (Rust/Rocket + SQLCipher) + Frontend (Vue/TS)

## Проблема

Нет журнала действий пользователей и администраторов. Локальному
администратору нужна панель с детальным аудитом: кто, когда и что делал
(входы, скачивания сертификатов, управление CA/пользователями/группами),
с фильтрацией и ручной очисткой старых записей. Панель доступна **только
локальному администратору**.

## Решения, зафиксированные на этапе brainstorming

- **Объём логирования:** значимые серверные действия (audit trail), не
  клики по UI. «Куда нажимал» на бэкенде не наблюдаемо без отдельного
  beacon-эндпоинта — сознательно НЕ реализуем, чтобы не плодить шум и
  инфраструктуру.
- **Очистка:** только ручная — кнопка в UI с выбором периода. Без
  фоновой автоочистки.
- **Набор полей:** базовый (кто/когда/действие/объект/результат/деталь) +
  nullable `ip`, заполняемый **только** для событий `login`/`logout`.
- **Доступ:** guard `AuthenticatedLocalAdmin`, гейтинг UI по
  `isLocalAdmin`.

## Хранилище — миграция `16-auditlog`

Новая таблица `audit_log` в той же зашифрованной БД (SQLCipher).

| поле | тип | назначение |
|---|---|---|
| `id` | INTEGER PRIMARY KEY | |
| `ts` | INTEGER NOT NULL | unix-время события (секунды) |
| `actor_id` | INTEGER NULL | id пользователя / сервис-аккаунта; NULL для анонимного |
| `actor_label` | TEXT NOT NULL | имя/email; при неудачном логине — введённый логин |
| `actor_type` | TEXT NOT NULL | `user` / `service` / `anonymous` |
| `action` | TEXT NOT NULL | код действия (см. `AuditAction`) |
| `target_type` | TEXT NULL | `ca` / `certificate` / `user` / `group` / `service_account` / `settings` |
| `target_id` | TEXT NULL | id объекта |
| `target_label` | TEXT NULL | имя объекта (CN, имя CA…) |
| `result` | TEXT NOT NULL | `success` / `failure` |
| `detail` | TEXT NULL | краткая деталь: формат скачивания, причина отказа |
| `ip` | TEXT NULL | заполняется только для `login` / `logout` |

Индексы: `ts`, `actor_id`, `action`.

`detail` — одна строка контекста (не отдельные структурированные поля),
остаётся в рамках «базового» набора: без неё «что качал» теряет смысл
(формат PEM/bundle/fullchain).

## Backend

### Типы
- `AuditAction` (enum) в `backend/src/data/enums.rs` — строковый код действия.
- `AuditResult` (enum) — `Success` / `Failure`.
- `AuditEntry` (входной объект для записи) и `AuditLogRow` (строка выдачи)
  в `backend/src/data/objects.rs`.
- `AuditFilter` — параметры фильтрации (`actor_id`, `action`, `from`, `to`,
  `result`).

### Методы `db.rs`
- `insert_audit(entry: AuditEntry) -> Result<()>`
- `query_audit(filter: AuditFilter, limit, offset) -> Result<(Vec<AuditLogRow>, i64)>`
  — возвращает страницу строк и общее количество для пагинации.
- `purge_audit(before_ts: i64) -> Result<usize>` — удаляет записи
  `ts < before_ts`, возвращает число удалённых.

### Хелпер записи
Запись в аудит **не блокирует** и **не роняет** основной запрос: любая
ошибка `insert_audit` логируется через `tracing::warn` и игнорируется.
Аудит — побочный эффект, отказ аудита не должен превращать успешную
операцию в ошибку для пользователя.

### Точки логирования (явные вызовы)
Выбран подход **явных вызовов** в бизнес-точках, а не Rocket fairing:
fairing видит только HTTP-запрос и не знает объекта операции и её
бизнес-результата (например, отказ авторизации внутри обработчика).

Actor извлекается из `Claims` (`id`, `is_local`, `is_service`, роль).
Для неудачного логина actor неизвестен → `actor_type = anonymous`,
`actor_label` = введённый логин.

Логируемые действия:
- `login` (success/failure), `logout` — с заполнением `ip`.
- `download_certificate` (с `detail` = формат), получение пароля/секрета
  сертификата.
- CA: `create_ca`, `import_ca`, `delete_ca`.
- Сертификаты: `revoke_certificate`, `delete_certificate`.
- Пользователи: create/update/delete.
- Группы: create/update/delete.
- Сервис-аккаунты: create/delete.
- Настройки: `update_settings`.

### Эндпоинты (guard `AuthenticatedLocalAdmin`)
Регистрируются в `backend/src/lib.rs` в общий mount под `/api`.

- `GET /api/audit?actor=&action=&from=&to=&result=&limit=&offset=`
  → `{ rows: AuditLogRow[], total: number }`
- `DELETE /api/audit?before=<ts>` → `{ deleted: number }`

Оба возвращают `403` для не-local-admin (обеспечивается guard).

## Frontend

- `frontend/src/components/AuditTab.vue` — новая вкладка.
- Роут `audit` в `frontend/src/router/router.ts`; пункт меню и роут-гард
  показываются только при `authStore.isLocalAdmin` (как у прочих
  local-admin вкладок).
- Методы API в `frontend/src/api/*` и типы в `frontend/src/types/*`.
- Строки локализации в `frontend/src/locales/*`.

### UI
- Таблица со столбцами: время / кто / действие / объект / результат
  (+ `ip` в детализации строки, где он есть).
- Фильтры сверху: пользователь, действие (select по `AuditAction`),
  период (from–to), результат.
- Пагинация server-side (`limit`/`offset`, `total` из ответа).
- Кнопка **«Очистить старые»** → выбор периода (старше 30 / 90 / 180 дней
  / всё) → подтверждающий диалог → `DELETE /api/audit?before=<ts>`.

## Тестирование

### Backend integration
- Миграция 16 создаёт таблицу `audit_log` с ожидаемыми колонками/индексами.
- `insert_audit` + `query_audit` с фильтрами по actor / action / period /
  result возвращают корректные подмножества и `total`.
- `purge_audit` удаляет записи старше границы и **не трогает** свежие;
  возвращает верный счётчик.
- `GET /api/audit` и `DELETE /api/audit` под не-local-admin → `403`.
- Неудачный логин пишет запись `actor_type=anonymous` с введённым логином
  и заполненным `ip`.
- `download_certificate` пишет запись с `target_type=certificate` и
  форматом в `detail`.

### Frontend
- `vue-tsc --noEmit -p tsconfig.app.json` проходит чисто.

## Вне scope (YAGNI)
- Логирование кликов/навигации по UI (beacon-эндпоинт).
- Фоновая автоочистка по расписанию.
- Экспорт логов, стриминг во внешние SIEM.
- IP/user-agent для всех событий, кроме login/logout.
