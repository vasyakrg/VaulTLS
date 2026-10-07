# Report: JWT в ответе логина (`include_token`)

- **Дата:** 2026-10-07
- **Профиль:** bugfix + feature
- **Статус:** Done

## Задача

Админ авторизуется логином/паролем и хочет использовать его токен как
`Authorization: Bearer` (например, для `DELETE /api/acme/accounts/<id>`).
Получал отказ — разобрались почему и починили.

## Диагноз

Кука `auth_token` ставится через `jar.add_private(...)` — Rocket **шифрует**
значение секретом сервера. В `Set-Cookie` лежит ciphertext, а не JWT; сырой
токен при человеческом логине вообще не покидает сервер. Поэтому извлечённая
из куки строка как Bearer не работает: `authenticate_auth_token` не может
декодировать JWT → 401 «Session expired or not authenticated» (гард
`AuthenticatedPrivileged` на `DELETE /acme/accounts/<id>` тут ни при чём —
до него запрос не доходит). Сервисные токены работают как Bearer, потому что
`POST /auth/token` возвращает `access_token` в теле.

## Решение

`POST /api/auth/login` опционально возвращает сырой JWT в теле:

```json
{ "email": "admin@example.com", "password": "…", "include_token": true }
```

→ `200 {"access_token": "eyJ…", "token_type": "Bearer", "expires_in": 3600}`

- Без `include_token` (или `false`) — поле `access_token` из ответа
  пропускается (`skip_serializing_if`); фронтенд на тело не смотрит, ничего
  не ломает.
- Кука ставится как и раньше (браузерная сессия с slide-renewal).
- Токен человеческий: TTL 1 час (`SESSION_TTL_SECS`), зарегистрирован в
  JTI-хранилище, logout инвалидирует; Bearer-использование slide-renewal не
  получает — через час нужен повторный логин.

## Изменённые файлы

| Файл | Что |
|---|---|
| `backend/src/data/api.rs` | `LoginRequest.include_token` (serde default), структура `LoginResponse` |
| `backend/src/api.rs` | `login` возвращает `Json<LoginResponse>` |
| `backend/src/auth/session_auth.rs` | `SESSION_TTL_SECS` → `pub(crate)` |
| `backend/tests/api/api_test_acme.rs` | тест полного сценария |
| `backend/tests/common/test_client.rs`, `tests/api/api_test_safety.rs` | инициализаторы `LoginRequest` + новое поле |

## Validation

- `admin_login_token_works_as_bearer_on_acme_admin_routes`: логин с
  `include_token` → токен в теле; без флага — поля нет; Bearer-токен админа
  проходит `DELETE /acme/accounts/<id>` (аккаунт деактивирован)
- Все 8 ACME-тестов зелёные; фронтенд не затронут
- Полный `cargo test`: 2 известных предсуществующих фейла, новых нет

## Ограничения (зафиксировано осознанно)

1. Токен в теле ответа — тот же сессионный JWT с теми же правами и TTL 1 час;
   отдельного «длинного» админ-токена нет (если понадобится — отдельная
   задача, например API-ключи).
2. Включение токена в тело снижает защиту от XSS-экфильтрации сессии для
   этого запроса; по умолчанию выключено — браузерный фронтенд флаг не
   использует.
