# Report: отказ ACME-регистрации с чужим ключом при переиспользовании EAB

- **Дата:** 2026-10-06
- **Профиль:** bugfix (диагностика «Signature verification failed» при выпуске через ACME)
- **Статус:** Done

## Задача

При проверке ACME-сервера (новый CA, аккаунт с auto_validate и доменами
`*.haproxy-viz.internal`) выпуск через внешний клиент падал:

```
acme order: 400 urn:ietf:params:acme:error:malformed: Signature verification failed
```

## Диагноз

Подпись в JWS проверяется всегда против **сохранённого** JWK аккаунта
(`acme/guard.rs` → `acme/jws.rs::authenticate_jws`). Сама проверка подписи
корректна (raw→DER для ES256 есть, signing input верный). Проблема — на шаге
раньше, в `POST /api/acme/new-account`:

```
let final_account = if account.acme_jwk.is_some() {
    account.clone()          // EAB kid уже привязан — возвращаем аккаунт КАК ЕСТЬ
} else { ...регистрация... };
```

Если EAB-креды (kid + HMAC) уже были использованы для регистрации с ключом K1
(например, первым запуском того же клиента), то повторный `new-account` с тем
же kid, но **новым** ключом K2 проходил EAB-проверку (HMAC зависит только от
секрета, а payload JWK сверяется с предъявленным, а не с сохранённым) и
молча возвращал 201 + kid аккаунта, зарегистрированного с K1. Клиент уходил
подписывать new-order ключом K2 под kid с сохранённым K1 → на первый же
POST «Signature verification failed» — без единого указания на реальную
причину (рассинхрон ключей на регистрации).

## Решение

`backend/src/acme/routes.rs` — ветка уже-зарегистрированного EAB kid:

- предъявленный ключ совпадает с сохранённым (сравнение thumbprint'ов) →
  **200 OK** с существующим kid — идемпотентная повторная регистрация
  (RFC 8555 §7.3.1 требует 200 для известного ключа; раньше отдавалось 201);
- ключ зарегистрирован за другим аккаунтом → **403 unauthorized**
  `account key is already registered to another ACME account`;
- ключ незнакомый (EAB-креды заняты другим ключом) → **403 unauthorized**
  `EAB credentials are already bound to a different account key`.

Теперь рассинхрон ключей диагностируется на регистрации понятной ошибкой, а
не на заказе непонятной.

Для интеграционных тестов (`backend/src/lib.rs`, `settings.rs`):
`create_test_rocket` включает ACME (`Settings::set_acme_enabled`, без записи
в файл), монтирует `/api/acme` + `NonceFairing` и админские ACME-маршруты —
раньше протокол в тестах вообще не был смонтирован.

## Изменённые файлы

| Файл | Что |
|---|---|
| `backend/src/acme/routes.rs` | ветка re-registration в `new_account`: сверка thumbprint, 200/403, RFC-корректные статусы |
| `backend/src/settings.rs` | `Settings::set_acme_enabled()` (для тестового рокета) |
| `backend/src/lib.rs` | `create_test_rocket`: ACME enabled, mount `/api/acme` + `NonceFairing`, админские ACME-роуты в обоих монтированиях |
| `backend/tests/api/api_test_acme.rs` | новый: 3 интеграционных теста (JWS/EAB-хелперы на openssl) |
| `backend/tests/api/mod.rs` | `mod api_test_acme` |

## Validation

- Новые тесты 3/3: same-key re-registration → 200 + тот же kid + успешный
  new-order (ES256-подпись end-to-end); other-key → 403 с явным текстом
  (и заказ старым ключом продолжает работать); wildcard-домен `*.x` не
  пропускает двухлейбловое имя → 403 rejectedIdentifier
- `cargo clippy --all-targets`: новых предупреждений нет
- Полный `cargo test`: см. примечание ниже (2 предсуществующих фейла)

## Ограничения и что проверить на стенде

1. **Домен аккаунта.** `*.haproxy-viz.internal` матчит ровно ОДИН лейбл:
   `probe-01.haproxy-viz.internal` — да, `probe-01.test.haproxy-viz.internal` —
   НЕТ (поймает `rejectedIdentifier`). Варианты: добавить в аккаунт
   `*.test.haproxy-viz.internal`, использовать `**.haproxy-viz.internal`
   (многоуровневый wildcard) или запрашивать однослотовое имя.
2. **EAB-креды «заняты» первой регистрацией.** После обновления повторный
   запуск клиента с новым ключом и теми же EAB получит явный 403. Лечение:
   удалить ACME-аккаунт в UI и создать новый (свежие EAB), либо настроить
   клиент на переиспользование сохранённого аккаунтного ключа — тогда он
   получит 200 и продолжит работать со своим kid.
3. Многоуровневый wildcard `**.` — нестандартное расширение допуска доменов
   VaulTLS (RFC-клиентам такие имена в order не передать; `**.` полезен
   только как паттерн allowlist).
4. Повторная регистрация тем же ключом теперь отвечает 200 (RFC), а не 201.
   Стандартные клиенты на это не опираются, но зафиксировано.
