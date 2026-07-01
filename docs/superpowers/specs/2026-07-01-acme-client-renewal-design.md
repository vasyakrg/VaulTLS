# ACME-клиент: certbot-подобное продление сертификатов

Дата: 2026-07-01
Область: `backend/src/acme_client/`, `backend/src/notification/notifier.rs`, `backend/src/db.rs`, `backend/migrations/`, `frontend` (кнопка renew + тип заказа).

## Проблема

«Renew» для ACME-клиентских (Let's Encrypt) сертов как отдельной операции не существует:

1. Кнопка renew в UI (`AcmeClientTab.vue:412 openNewOrderModal(renewFrom)`) лишь предзаполняет форму нового заказа — это создание нового order с нуля.
2. `create_order` (`client.rs:95–108`) собирает dns-01 TXT для **каждой** authorization, не проверяя `authz.status`. Даже когда LE переиспользует **valid**-авторизацию (~30 дней), пользователю показывают лишнюю пару TXT и всё равно гоняют `set_ready`.
3. `insert_acme_client_certificate` (`db.rs:1243`) всегда `INSERT` → новый cert-row с новым ID. Обновления «на месте» нет → после продления появляется второй серт с другим Id.
4. **Латентный баг:** notifier'ский `Renew`-путь (`handle_expiry`, `notifier.rs:77`) не отделяет ACME-серты от internal-CA. Если у LE-серта `renew_method ∈ {Renew, RenewAndNotify}`, notifier перевыпускает его через **внутренний CA** (`get_latest_tls_ca()` + `TLSCertificateBuilder::try_from`) c новым ключом и `insert_user_cert` → чужой CA, новый ID. Плюс окно там 7 дней (`in_a_week`), а не 30.

## Решения (зафиксированы)

- Модель: **полу-авто + уведомление** (не RFC2136).
- Ключ при продлении: **новый** каждый раз (certbot default; `finalize()` генерирует сам).
- Окно продления: **30 дней** до истечения (фиксировано).
- Охват: **opt-in** через `renew_method` (Renew / RenewAndNotify).

## Не входит в объём (YAGNI)

- RFC2136 / любой DNS-API для авто-публикации TXT.
- Reuse приватного ключа (--reuse-key).
- Настраиваемое окно продления.
- Авто-продление сертов без явного `renew_method`.

## Архитектура

### Блок A — переиспользование valid-авторизации

**`backend/src/acme_client/client.rs`, `create_order`:**
Внутри цикла по `order.authorizations()` собирать `TxtRecord` **только** для authz со `status == AuthorizationStatus::Pending`. Для `Valid` — пропускать (challenge не нужен). Результат: `CreatedOrder.txt_records` пуст, если все авторизации уже валидны.

**`issue_order`, шаг set_ready (`client.rs:220–226`):**
Вызывать `challenge.set_ready()` только когда авторизация в состоянии `Pending`. Для `Valid` авторизаций пропускать (иначе `set_ready` на уже валидном challenge вернёт ошибку). Проверять `authz` (Deref к `AuthorizationState`) `.status` перед `challenge(ChallengeType::Dns01)`.

DNS-precheck (`check_txt_records`) при пустом `txt_records` тривиально проходит (нечего искать → `missing` пуст → `ok`), так что путь «authz валидна → без TXT → сразу finalize» работает без изменений в precheck.

### Блок B — продление «на месте» (schema + issue-путь)

**Миграция `backend/migrations/14-acmeclientrenewal/`:**
- `up.sql`: `ALTER TABLE acme_client_orders ADD COLUMN renews_cert_id INTEGER;`
- `down.sql`: `ALTER TABLE acme_client_orders DROP COLUMN renews_cert_id;`

**Тип `AcmeClientOrder`** (`types.rs`) += `pub renews_cert_id: Option<i64>`; `acme_client_order_from_row` читает новый столбец; `insert_acme_client_order` принимает `renews_cert_id: Option<i64>` и пишет его в INSERT.

**DB:**
- Новый метод `update_acme_client_certificate_in_place(cert_id, pkcs12_der, valid_until) -> Result<()>`:
  `UPDATE user_certificates SET data = ?, valid_until = ?, created_on = ? WHERE id = ?` (created_on = now; id/name/user_id/renew_method/acme_provider_id/type сохраняются). Не трогает password (тот же пустой).
- Новый метод `get_acme_client_order_by_cert_id(cert_id) -> Result<Option<AcmeClientOrder>>`:
  `SELECT ... FROM acme_client_orders WHERE cert_id = ?1 ORDER BY id DESC LIMIT 1` — исходный заказ, из которого берём `domain / provider_id / include_wildcard` при продлении.

**Issue-путь (`acme_client/routes.rs::issue_acme_client_order`):**
После успешного `issue_order` + `pack_issued_certificate`:
- если `order.renews_cert_id` задан → `update_acme_client_certificate_in_place(renews_cert_id, pkcs12_der, valid_until)` (серт обновлён на месте, тот же ID);
- иначе → `insert_acme_client_certificate(...)` как сейчас.
В обоих случаях `update_acme_client_order_status(id, "valid", Some(cert_id_or_renews_id), None)`.

### Блок C — полу-авто крон (notifier) + фикс латентного бага

**`backend/src/notification/notifier.rs`:**

0. **Проброс settings:** `watch_expiry(db, mailer_mutex)` сейчас не имеет доступа к настройкам. Расширить сигнатуру до `watch_expiry(db, mailer_mutex, settings: Settings)` (тип `Settings` — Arc-backed, клонируемый) и обновить вызов в `lib.rs:183`. ACME-ветке нужны `settings.get_acme_dns_resolver()` и `settings.get_acme_accept_invalid_certs()`. Providers/аккаунты берутся из БД (`get_acme_client_provider`).

1. **Фикс латентного бага:** в цикле продления internal-CA (`handle_expiry`, ветки `Renew | RenewAndNotify`) исключить серты с `cert.acme_provider_id.is_some()` — они не должны идти через `TLSCertificateBuilder`/внутренний CA. Проще всего: в фильтре основного цикла разделить обработку — ACME-серты уходят в новую функцию, остальные в существующий `handle_expiry`.

2. **Новая ACME-ветка** `handle_acme_renewal(cert, db, state/settings, mailer)`:
   Условия отбора (в цикле тикера, отдельным фильтром): `cert.acme_provider_id.is_some()` && `cert.renew_method ∈ {Renew, RenewAndNotify}` && `cert.valid_until < now + 30 дней`.
   - **Гуард от дублей:** если существует незавершённый renew-заказ для серта (`renews_cert_id = cert.id` со статусом `pending_dns` | `ready`) — пропустить тик (не плодить заказы). Требуется db-метод `get_active_renewal_order_for_cert(cert_id) -> Result<Option<AcmeClientOrder>>` (`WHERE renews_cert_id = ?1 AND status IN ('pending_dns','ready') LIMIT 1`).
   - Иначе: найти исходный заказ (`get_acme_client_order_by_cert_id`) → взять `provider`, `domain`, `include_wildcard`. Вызвать `client::create_order(provider, domain, include_wildcard)`; при новых creds — сохранить. Вставить заказ через `insert_acme_client_order(..., renews_cert_id = Some(cert.id))`.
     - Если `created.txt_records` пуст (authz валидна) → сразу `client::issue_order(...)` (resolver+accept_invalid_certs из settings, txt_records=[]), спаковать, `update_acme_client_certificate_in_place(cert.id, ...)`, статус заказа `valid`. Если `RenewAndNotify` → `notify_renewed_certificate`.
     - Если `txt_records` непусты → заказ остаётся `pending_dns`; отправить письмо «нужно добавить TXT и нажать Issue» (переиспользовать `notify_old_certificate` или новый шаблон). Пользователь дожимает вручную (Блок B обновит серт на месте).
   - `renew_method` для ACME-сертов **НЕ сбрасывается** в `None` (в отличие от internal-CA пути на `notifier.rs:47`) — иначе следующий цикл не продлит. Reset применять только к не-ACME сертам.

**Окно:** для ACME использовать 30 дней (`now + 1000*60*60*24*30`), не общий `in_a_week`.

### Блок D — кнопка renew в UI

`AcmeClientTab.vue`: renew-действие оперирует `AcmeClientOrder` (у него есть `cert_id`). Пробросить `renews_cert_id = renewFrom.cert_id` в запрос создания заказа, чтобы ручной renew тоже (а) переиспользовал authz (Блок A) и (б) обновлял серт на месте (Блок B).

- `CreateOrderRequest` (backend `types.rs` + frontend `AcmeClient.ts`) += `renews_cert_id?: Option<i64>/number | null`.
- `create_acme_client_order` route пробрасывает `req.renews_cert_id` в `insert_acme_client_order`.
- Frontend store `newOrder` / форма прокидывает поле; кнопка renew ставит `renews_cert_id = renewFrom.cert_id`, обычное создание — `null`.

## Поток

- **Авто (крон), authz валидна:** тик → окно 30д → нет активного renew-заказа → create_order (TXT пуст) → issue → cert обновлён на месте → (RenewAndNotify) письмо. Полностью unattended.
- **Авто (крон), authz протухла:** тик → create_order (TXT есть) → заказ pending_dns + письмо «добавь TXT» → пользователь Check&Issue → cert обновлён на месте.
- **Ручной renew:** кнопка → заказ с renews_cert_id → если TXT пуст, сразу Issue; иначе показать TXT → cert обновлён на месте.

## Тесты

- Backend unit: `create_order` фильтрация по статусу — вынести чистую функцию отбора pending-authz и покрыть (без сети). `missing_txt_values`/precheck при пустом наборе уже покрыты.
- Backend unit: `update_acme_client_certificate_in_place` — вставить cert, обновить, проверить что id тот же, valid_until/created_on обновились, name/user_id/renew_method сохранены.
- Backend unit: гуард дублей — `get_active_renewal_order_for_cert` возвращает существующий незавершённый заказ.
- Frontend: `vue-tsc` зелёный.
- Ручная проверка на проде (LE staging): продление при валидной authz (без TXT) и при протухшей (с TXT), отсутствие второго cert-row.

## Совместимость / риски

- Существующие internal-CA renew и разовый issue не меняются по семантике (ACME только выделяется из общего пути).
- Миграция аддитивна (nullable колонка); старые заказы имеют `renews_cert_id = NULL` → ведут себя как раньше (INSERT).
- Тикер: интервал прежний; ACME-ветка идемпотентна за счёт гуарда от дублей.
