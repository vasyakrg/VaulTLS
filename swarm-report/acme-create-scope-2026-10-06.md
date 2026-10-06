# Report: скоуп `acme:create` для сервисных аккаунтов

- **Дата:** 2026-10-06
- **Профиль:** business-feature
- **Статус:** Done

## Задача

У сервисных аккаунтов есть скоупы `cert:read` и `cert:issue`. Автоматизация
(CI/сервисы) должна уметь полноценно выпускать и обновлять себе TLS
сертификаты через ACME: добавить скоуп, разрешающий `POST /api/acme/accounts`.

## Решение

**Скоуп `acme:create`** (нейминг в ряд `cert:read`/`cert:issue`):

- `backend/src/api.rs`: добавлен в `ALLOWED_SCOPES` (теперь 3). В
  `SELF_SERVICE_SCOPES` НЕ добавлен — выдавать его может только админ, как
  и `cert:issue` (заведение ACME-аккаунтов — инфраструктурная привилегия).
- `backend/src/acme/admin.rs` — `create_acme_account`: гард заменён с
  `AuthenticatedPrivileged` на `Authenticated` с ручной проверкой:
  сервис → нужен `acme:create`; человек → роль Admin (включая OIDC-админов,
  как и раньше). Остальные ACME-маршруты (протокол `/api/acme/*`,
  редактирование/деактивация аккаунтов, заказы) не менялись: протокол
  публичный с EAB-аутентификацией, админские операции — прежние гарды.

**Как это работает для сервиса:**

1. `POST /auth/token` (client_id/secret) → Bearer JWT со скоупами.
2. `POST /api/acme/accounts` c Bearer → EAB KID+HMAC (секрет показывается
   один раз — сервис обязан сохранить).
3. Дальше стандартный ACME-протокол (`/api/acme/directory` → new-account с
   EAB → new-order → challenge → finalize) — он публичный и в скоупах не
   нуждается.
4. Выпущенные сертификаты привязываются к владельцу токена
   (`create_acme_account` пишет `user_id = claims.id`, для сервиса это его
   owner) → читаются/скачиваются по `cert:read`, обновление — новый заказ
   по тем же EAB-кредам.

**Фронтенд** (`ServiceAccountsModal.vue`, локали en/es): третий чекбокс
«Create ACME accounts (acme:create)» — только для админа, как `cert:issue`.

**Документация**: `docs/superpowers/specs/2026-06-26-service-accounts-jwt-design.md`
— скоупы и правила авторизации дополнены.

## Изменённые файлы

| Файл | Что |
|---|---|
| `backend/src/api.rs` | `ALLOWED_SCOPES` += `acme:create` |
| `backend/src/acme/admin.rs` | `create_acme_account`: `Authenticated` + проверка скоупа/роли |
| `frontend/src/components/ServiceAccountsModal.vue` | чекбокс `acme:create` (admin only) |
| `frontend/src/locales/en.json`, `es.json` | `serviceAccounts.scopeAcmeCreate` |
| `docs/superpowers/specs/2026-06-26-service-accounts-jwt-design.md` | скоупы и §5 |
| `backend/tests/api/api_test_acme.rs` | +2 теста |

## Validation

- `service_with_acme_create_scope_can_create_account`: сервисный токен
  создаёт ACME-аккаунт (EAB-креды в ответе) и по ним проходит регистрацию
  через протокол
- `service_without_acme_create_scope_is_rejected`: токен только с
  `cert:read` → 403
- Все 7 ACME-тестов зелёные; frontend: `vue-tsc` + build + vitest 36/36
- Полный `cargo test`: 2 известных предсуществующих фейла, новых нет

## Ограничения (зафиксировано осознанно)

1. Скоуп даёт только создание ACME-аккаунтов. Deactivate/purge аккаунтов,
   revoke/delete заказов — по-прежнему локальный админ; сервис управляет
   своей жизнью через протокол (new-order по тем же EAB-кредам).
2. EAB-креды показываются в ответе один раз — сервис должен хранить их
   сам; повторный `new-account` с теми же EAB и тем же ключом даст 200
   (см. acme-eab-rebind-2026-10-06), с другим ключом — 403.
3. Сервис не может перечислить свои ACME-аккаунты (`GET /acme/accounts` —
   админский). Если понадобится сервисная самодиагностика — отдельный
   скоуп/маршрут.
4. `SELF_SERVICE_SCOPES` не расширялся: обычный пользователь-владелец не
   может сам выдать своему сервису `acme:create`.
