# Report: аудит — подпись сервисных аккаунтов, IP, имена сертов в target

- **Дата:** 2026-09-09
- **Профиль:** bugfix / audit-log quality
- **Статус:** Done

## Задача

Перепроверка матрицы прав (кнопка «Update certificate») и три замечания к журналу аудита:

1. Сервисные аккаунты не подписываются в журнале — нужен логин владельца.
2. У сервисных аккаунтов не определяется IP запроса.
3. В target у сервисных операций виден только `certificate #15` — нужно имя серта.

## Расследование

**Кнопка Update certificate.** Фронт (`OverviewTab.vue::canUpdate`) зеркалит бэк
(`PUT /certificates/<id>`): владелец ИЛИ локальный админ, плюс требования к серту —
импортированный, не отозван, не ACME, тип TLS. Матрица фронт/бэк консистентна; расхождений
не найдено. Найден смежный баг: Delete-кнопка в активной таблице гейтилась `authStore.isAdmin`
вместо `canManage` (владелец-не-админ не видел кнопку удаления своего серта; OIDC-админ видел
и ловил 403 — бэк требует владельца или локального админа). Исправлено на `canManage`
(как уже было в таблице отозванных).

**Аудит.** Все три замечания подтвердились:

| # | Причина | Место |
|---|---|---|
| 1 | `audit_actor` для сервиса писал `service:<account_id>` без имени и владельца | `api.rs::audit_actor` |
| 2 | `ip` передавался только в `login`/`logout`; все остальные 20+ вызовов `record_audit` получали захардкоженный `None` | `api.rs` |
| 3 | `target_label = None` в download/fetch_password/delete/revoke → фронт рендерил `target_type #id` = `certificate #15` | `api.rs`, рендер `AuditTab.vue:47` |

## Решение

1. **Guard'ы несут IP.** `Authenticated` / `AuthenticatedPrivileged` / `AuthenticatedLocalAdmin`
   получили поле `ip: Option<String>` — резолвится один раз в `from_request` через
   `request.client_ip()` (учитывает `ip_header` за прокси; тот же источник, что у
   `Option<IpAddr>`-экстрактора логина). Все вызовы `record_audit` в `api.rs` и ACME-renew
   в `acme_client/routes.rs` теперь передают его — IP пишется для всех операций, не только
   сервисных.
2. **Подпись сервисного аккаунта:** `audit_actor` достаёт из БД имя аккаунта и логин
   владельца → лейбл `<аккаунт> (<владелец>)`, например `deploy-bot (vasya)`. Если аккаунт
   уже удалён — fallback `service:<id>`. `actor_id`/`actor_type` не изменились (фильтры работают).
3. **target_label:** download (zip и одиночный), `fetch_certificate_password`,
   `delete_certificate`, `revoke_certificate` пишут CN серта. В UI будет `example.com #15`.
   Для fetch_password добавлен лёгкий `db.get_user_cert_name()` (SELECT name без data-блоба).

Фоновые записи от notifier (автопродление) остались без IP — это не сетевые запросы.

## Изменённые файлы

| Файл | Что |
|---|---|
| `backend/src/auth/session_auth.rs` | поле `ip` в трёх guard'ах, резолв из `client_ip()` |
| `backend/src/api.rs` | `audit_actor`: имя+владелец сервиса; все вызовы: ip из guard'а; target_label для сертификатных действий |
| `backend/src/db.rs` | `get_user_cert_name()`; импорт `Name` |
| `backend/src/acme_client/routes.rs` | ip в аудите ACME-renew |
| `frontend/src/components/OverviewTab.vue` | Delete-кнопка активной таблицы: `isAdmin` → `canManage` |

## Validation

- `cargo check`, `cargo test` — 106 passed; 1 failed (`test_ssh_revocation_and_krl`) —
  падает и на чистом main (локальный ssh-keygen отвечает 255), не регресс
- `cargo clippy` — без новых предупреждений относительно baseline
- frontend: `vitest` 36/36, `npm run build` (type-check + build) — зелёные

## Замечания (вне скоупа, зафиксировано)

1. Кнопка Update остаётся скрытой для: сгенерированных (не импортированных) сертов, ACME,
   SSH-сертов, отозванных — это осознанные ограничения бэка, не баг.
2. У OIDC-админа (`is_local=false`) нет ни Update/Delete/Revoke на чужие серты, ни вкладок
   Groups/Audit — бэк его так же ограничивает; фронт и бэк консистентны.
3. `fr.json` не содержит секции `certVersions` — французская локаль падает в английский fallback.
