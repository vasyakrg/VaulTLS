# Дизайн: ACME-клиент для Let's Encrypt (dns-01, ручной режим)

Дата: 2026-06-29
Статус: согласован, готов к плану реализации

## 1. Цель и контекст

VaulTLS должен уметь выступать **ACME-клиентом** к публичным центрам сертификации
(Let's Encrypt и совместимым) и получать публичные TLS-сертификаты через challenge
**dns-01**. DNS-инфраструктура (bind9) сейчас без автоматизации, поэтому процесс
**полуручной**: VaulTLS генерирует TXT-записи, пользователь копирует их и руками
вносит в зону bind9, после чего VaulTLS завершает выдачу.

Полученные сертификаты — **хранилище для выгрузки**: сохраняются рядом с остальными,
пользователь скачивает их из обычного раздела Overview и сам ставит на свои сервисы.

### Важное разграничение

В кодовой базе уже есть модуль `backend/src/acme/` — это VaulTLS **в роли
ACME-сервера** (directory, JWS, nonce, EAB, валидация чужих challenge; таблицы
`acme_accounts`, `acme_orders`, `acme_nonces`). Новая фича — **встречное
направление** (VaulTLS как ACME-клиент) и реализуется в отдельном модуле, чтобы
исключить путаницу.

## 2. Принятые решения

| Вопрос | Решение |
|---|---|
| Назначение сертов | Хранилище для выгрузки (скачивание из Overview) |
| Охват заказа | Базовый домен + опционально wildcard (`example.com` + `*.example.com`) |
| Продление | Напоминание (фоновый notifier) + кнопка «Продлить» (повтор выдачи) |
| Провайдеры | Несколько ACME-провайдеров; пресеты LE production/staging; ZeroSSL/BuyPass через EAB |
| Реализация клиента | Библиотека `instant-acme` |
| Хранение сертов | Общая таблица `user_certificates` (`ca_id` nullable + признак источника) |
| Размещение UI | Новая вкладка «Let's Encrypt» |

## 3. Реализация ACME-клиента: `instant-acme`

Используем крейт [`instant-acme`](https://github.com/djc/instant-acme) (RFC 8555,
async, pure-Rust). Обоснование:

- Опирается на `rustls` + `aws-lc-rs` — **уже подключены** в `backend/Cargo.toml`.
- Нативно поддерживает ручной dns-01: `challenge.key_authorization()?.dns_value()`
  даёт значение TXT, `challenge.set_ready()` сигнализирует серверу.
- Поддерживает EAB (`ExternalAccountKey`) для ZeroSSL/BuyPass.
- Сериализует учётные данные аккаунта (`AccountCredentials`) — это позволяет
  восстанавливать аккаунт и заказ между HTTP-запросами и перезапусками сервиса.

Новый модуль: `backend/src/acme_client/` (имя осознанно отличается от `acme/`).

## 4. Модель данных (миграция 13)

Вся БД VaulTLS шифруется целиком (`encrypted.db3`), поэтому секреты (ключ аккаунта,
EAB hmac) хранятся в зашифрованном хранилище без отдельного пошифрового шифрования —
по тому же принципу, что существующий `acme_accounts.eab_hmac_key: Vec<u8>`.

### 4.1 Таблица `acme_client_providers`

Провайдер ACME (директория + зарегистрированный у неё аккаунт).

| Поле | Тип | Описание |
|---|---|---|
| `id` | INTEGER PK | |
| `name` | TEXT | Отображаемое имя (напр. «Let's Encrypt (prod)») |
| `directory_url` | TEXT | URL ACME-директории |
| `account_email` | TEXT | Контактный email аккаунта |
| `eab_kid` | TEXT NULL | EAB key id (для ZeroSSL/BuyPass) |
| `eab_hmac_key` | BLOB NULL | EAB HMAC-ключ (сырые байты) |
| `account_credentials` | TEXT NULL | JSON `AccountCredentials` от instant-acme; NULL до первой регистрации |
| `created_on` | INTEGER | UNIX ms |

Аккаунт регистрируется лениво при первом заказе у провайдера; результат
(`AccountCredentials`) сохраняется в `account_credentials` и переиспользуется.

**Пресеты при старте** (если таблица пуста — seed): LE production
(`https://acme-v02.api.letsencrypt.org/directory`) и LE staging
(`https://acme-staging-v02.api.letsencrypt.org/directory`). Email и регистрация —
при первом использовании.

### 4.2 Таблица `acme_client_orders`

Заказ на сертификат (живёт между двумя фазами ручного процесса).

| Поле | Тип | Описание |
|---|---|---|
| `id` | INTEGER PK | |
| `provider_id` | INTEGER FK → `acme_client_providers(id)` | |
| `domain` | TEXT | Базовый домен |
| `include_wildcard` | BOOLEAN | Добавлять ли `*.domain` |
| `status` | TEXT | `pending_dns` \| `ready` \| `valid` \| `failed` \| `expired` |
| `order_url` | TEXT | URL заказа у ACME-сервера (для восстановления) |
| `txt_records` | TEXT | JSON `[{ name, value }]` — записи для bind9 |
| `cert_id` | INTEGER FK → `user_certificates(id)` NULL | заполняется после выдачи |
| `error` | TEXT NULL | текст последней ошибки |
| `created_on` | INTEGER | UNIX ms |
| `expires_at` | INTEGER NULL | срок жизни заказа у ACME (~7 дней) |

### 4.3 Изменение `user_certificates`

- `ca_id` уже nullable — менять не требуется.
- Добавить колонку `acme_provider_id INTEGER NULL REFERENCES acme_client_providers(id) ON DELETE SET NULL`
  — признак того, что серт выдан внешним ACME-провайдером (а не внутренним CA).

В колонке «CA Name» (Overview) для таких сертов показываем имя провайдера вместо
имени внутреннего CA.

## 5. Поток выдачи (двухфазный, ручной dns-01)

### Фаза 1 — создать заказ и получить TXT

1. Пользователь: вкладка «Let's Encrypt» → «Новый сертификат» → выбирает провайдера,
   вводит домен, ставит галку wildcard.
2. Backend:
   - Восстанавливает/регистрирует аккаунт провайдера (`Account::builder().create(...)`,
     при наличии — из сохранённых `AccountCredentials`; с EAB, если задан).
   - `account.new_order(NewOrder::new([Dns(domain), Dns(*.domain)?]))`.
   - Перебирает `order.authorizations()`, для каждой берёт challenge `Dns01` и
     `key_authorization()?.dns_value()`.
   - Сохраняет заказ: `order_url`, `txt_records` (`_acme-challenge.<domain>` →
     значение(я)), статус `pending_dns`, `expires_at`. **`set_ready` не вызывается.**
3. UI показывает TXT-записи с кнопкой «Копировать» и подсказкой: «добавьте записи в
   зону bind9, поднимите serial, выполните `rndc reload`». Для wildcard — две записи
   с одинаковым именем `_acme-challenge.<domain>` и разными значениями (bind9
   допускает несколько TXT RR с одним именем).

### Фаза 2 — проверить и выпустить

4. Пользователь вручную вносит TXT в bind9, ждёт распространения, жмёт «Проверить и
   выпустить».
5. Backend:
   - **Предпроверка**: через `validate_dns01` (на `hickory-resolver`, уже есть в
     проекте) убеждается, что ожидаемые TXT реально видны в DNS. Если нет — заказ
     остаётся `pending_dns`, пользователю возвращается понятная ошибка (без обращения
     к ACME — это бережёт rate-limit).
   - Восстанавливает заказ: `account.order(order_url)`.
   - `challenge.set_ready()` по каждой авторизации → `order.poll_ready()` →
     `order.finalize()` (генерация ключа) → `order.poll_certificate()`.
   - Сохраняет сертификат и ключ в `user_certificates` (`ca_id = NULL`,
     `acme_provider_id = provider`), проставляет `cert_id` и статус `valid` в заказе.
6. Серт появляется в Overview и доступен для скачивания штатным механизмом.

### Продление

- Кнопка «Продлить» у выданного серта/заказа = повтор Фазы 1 (новый заказ, **новые**
  TXT — LE выдаёт новые значения каждый раз).
- Фоновый `notifier` (существующий тикер в `notification/notifier.rs`) шлёт
  напоминание о скором истечении. Авто-выпуск не делается — dns-01 ручной.

## 6. API (backend, под `/api`, admin-only)

- `GET    /api/acme-client/providers` — список провайдеров
- `POST   /api/acme-client/providers` — добавить провайдера (name, directory_url, email, eab?)
- `DELETE /api/acme-client/providers/<id>`
- `GET    /api/acme-client/orders` — список заказов
- `POST   /api/acme-client/orders` — Фаза 1: создать заказ → вернуть TXT-записи
- `POST   /api/acme-client/orders/<id>/issue` — Фаза 2: предпроверка + выпуск
- `DELETE /api/acme-client/orders/<id>`

Точные имена/формы уточняются на этапе плана; маршруты регистрируются через тот же
`openapi_get_routes!`, что и остальной API (видны в Scalar).

## 7. UI (frontend)

- Новый пункт меню «Let's Encrypt» + страница `AcmeClientTab.vue` (по образцу
  существующих вкладок и `AcmeTab.vue`):
  - Раздел «Провайдеры»: список, добавление (LE prod/staging — пресеты).
  - Раздел «Заказы»: список со статусами; мастер создания (домен + wildcard);
    экран показа TXT-записей с копированием; кнопка «Проверить и выпустить»; кнопка
    «Продлить».
- Выданные серты видны в Overview (колонка «CA Name» = имя провайдера).
- Локализация: ключи в `en.json` и `es.json` (`fr.json` пустой — не трогаем).

## 8. Обработка ошибок

| Ситуация | Поведение |
|---|---|
| TXT ещё не распространился | Предпроверка `validate_dns01` не пускает в Фазу 2; понятная ошибка |
| Rate-limit ACME | Минимизируем обращения предпроверкой; пресет staging для отладки |
| Заказ протух (>~7 дней) | Статус `expired`; предложить пересоздать |
| Challenge invalid у ACME | Статус `failed`, текст в `error`, возможность повторить |
| Сбой регистрации аккаунта/сети | Заказ не создаётся, ошибка пользователю |

## 9. Границы (YAGNI)

В объём **не** входит: автоматизация bind9 (RFC 2136/API), http-01 у внешних CA,
авто-renew без участия человека, отзыв (revoke) внешних сертов через ACME — может быть
добавлено позже отдельной итерацией.

## 10. Переиспользование существующего кода

- `hickory-resolver` + логика `validate_dns01` (`backend/src/acme/routes.rs`) — для
  предпроверки TXT (вынести/обобщить в общий helper).
- `rustls` + `aws-lc-rs` — общий крипто-провайдер для `instant-acme`.
- Фоновый `notifier` — напоминания об истечении.
- Механизм миграций (`backend/migrations/NN-*/up.sql`) — новая миграция 13.
- Шаблоны вкладок фронтенда и общий `BaseModal`/таблицы PrimeVue.
