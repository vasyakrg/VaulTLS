# Истечение сессии: фронт не реагировал на 401

**Дата:** 2026-09-22
**Профиль:** Bug Hunting
**Ветка:** main

## Симптом

После истечения токена пользователь не попадал на форму логина и токен не продлевался. Пользователь продолжал ходить по разделам и получать сообщения вида `Failed to fetch certificates: undefined`.

## Root cause — пять независимых дефектов

1. **Guard не срабатывал при переходах между разделами.**
   `frontend/src/router/router.ts` — проверка стояла в `beforeEnter` родительского роута `/`. Vue Router вызывает `beforeEnter` только при входе в родительскую запись извне, поэтому переходы `/overview → /users → /ca` (смена child-роута) проверку не запускали ни разу. Глобального `router.beforeEach` не было.

2. **Interceptor на 401 логаутил, но не редиректил.**
   `frontend/src/api/ApiClient.ts` вызывал `authStore.logout()` и оставлял пользователя на текущей странице.

3. **Источником правды был localStorage.**
   `stores/auth.ts` брал `isAuthenticated` из `localStorage['is_authenticated']`. Флаг жил вечно, JWT — 1 час. Cookie `HttpOnly`, её срок фронту не виден.

4. **401 возвращался без JSON-тела.**
   Rocket-guard'ы (`backend/src/auth/session_auth.rs`) отклоняют запрос статусом без тела, катчеров не было → HTML-страница Rocket. Сторы клеят `err.response.data.error` (~40 мест) → `undefined` в тексте ошибки.

5. **Механизма продления не существовало.**
   JWT ровно 1 час без продления, endpoint'а refresh нет, `JTI_STORE` — in-memory (рестарт бэкенда убивает все сессии).

Дополнительно: `views/LoginView.vue` делал `router.push('Overview')` — строка трактуется как path, не как имя роута.

## Решение

### Backend — скользящая сессия

`backend/src/auth/session_auth.rs`:
- `JTI_STORE` стал `HashMap<jti → exp>` — собственные часы отзыва + возможность вычищать мёртвые записи (`register_jti` подчищает при каждой выдаче; раньше набор рос бесконечно).
- В guard-пути (`authenticate_auth_token`) для cookie-сессий: если до `exp` осталось меньше 15 минут — выпускается новый токен и кладётся в ответ через `request.cookies().add_private(...)`. Активный пользователь не выпадает из сессии.
- Заменённый токен живёт ещё 60 секунд (`SESSION_RENEW_GRACE_SECS`) — запросы, уже улетевшие со старой cookie, не получают 401.
- Bearer-токены сервис-аккаунтов не продлеваются (они stateless и выдаются отдельно).
- `build_auth_cookie()` — один набор флагов cookie для password-login, OIDC-callback и продления (раньше флаги дублировались в трёх местах).

`backend/src/lib.rs`: катчеры `401`/`403` отдают `{"error": "..."}` — тот же формат, что у `ApiError`, чтобы фронт всегда имел читаемое сообщение.

### Frontend

- `src/router/authGuard.ts` (новый) + `router.beforeEach(authGuard)` — проверка на каждом переходе, включая переходы между табами. Роуты `/login` и `/first-setup` помечены `meta.public`.
- `src/api/errorInterceptor.ts` (новый) — нормализация тела ошибки (любой ответ получает `data.error`, Blob не трогается) и сигнал об истечении сессии на неожидаемый 401.
- `src/api/sessionExpired.ts` (новый) — мост между axios и роутером без циклического импорта; дедуп «пачки» 401 в окне 1 с, чтобы не было нескольких навигаций.
- `src/main.ts` — регистрация обработчика: `clearSession()` + `push({name:'Login', query:{redirect}})`.
- `src/stores/auth.ts` — `verifySession()` спрашивает `/auth/me`; `clearSession()` чистит состояние локально; `logout()` чистит состояние в `finally` даже при ошибке; легаси-флаг `is_authenticated` удаляется из localStorage.
- `src/views/LoginView.vue` — возврат на исходную страницу по `?redirect=`, только внутренние пути (отсечены `//`), иначе `{name:'Overview'}`.

## Проверки

| Проверка | Результат |
|---|---|
| `cargo build` | без предупреждений |
| `cargo test --lib` | 107 passed (7 новых в `sliding_session_tests`) |
| `cargo test` (интеграционные) | 106 passed, 1 failed — `test_ssh_revocation_and_krl`, падает и без этих правок (ssh-keygen/KRL на этой машине) |
| `npm run type-check` | чисто |
| `npm run test:unit` | 36 passed (25 новых: guard, interceptor, стор) |
| `npm run build-only` | успешно |

Ключевой тест — `near_expiry_cookie_is_reissued_on_authenticated_request`: реальный запрос через guard подтверждает, что cookie, добавленная внутри request guard, доходит до ответа.

## Не сделано

- E2E-проверка на проде (деплой не выполнялся) — ожидает решения.
- Рестарт бэкенда по-прежнему инвалидирует все сессии: `JTI_STORE` в памяти. Скользящая сессия это не лечит; для устойчивости к рестартам нужен persist jti в БД — отдельная задача.
