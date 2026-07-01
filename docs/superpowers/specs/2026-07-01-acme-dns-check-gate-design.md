# ACME dns-01: разделение проверки DNS и запуска выпуска

Дата: 2026-07-01
Область: `backend/src/acme_client/`, `frontend/src/components/AcmeClientTab.vue`, локали, store/api ACME-клиента.

## Проблема

Модалка «TXT Records» имеет одну кнопку **Check & Issue**, которая сразу вызывает
`set_ready` у ACME-сервера. Если CA не увидел TXT-записи, заказ уходит в необратимый
`invalid` — приходится создавать новый заказ с **новой парой TXT-значений** и снова
прописывать их в DNS-зону. Пользователь не может безопасно проверить готовность зоны,
не рискуя сжечь заказ.

## Цель

Разделить два действия:

1. **Проверить DNS** — только резолв TXT-записей через настроенный резолвер, без
   обращения к CA и без изменения статуса заказа. Можно повторять сколько угодно.
2. **Запустить выпуск** — существующий поток `issue` (`set_ready` → poll → finalize).
   Кнопка **неактивна**, пока в текущей сессии модалки не прошла успешная проверка DNS.

## Не входит в объём (YAGNI)

- Персист гейта «DNS проверен» в БД (состояние эфемерное, только во фронте).
- Авто-поллинг/фоновая проверка DNS.
- Любые изменения в логике общения с CA (кроме уже существующего precheck).

## Backend

### Общий хелпер

В `acme_client/client.rs`:

```rust
pub(crate) struct DnsCheckOutcome {
    pub ok: bool,
    pub expected: Vec<String>,
    pub found: Vec<String>,
    pub missing: Vec<String>,
}

/// Резолвит TXT `_acme-challenge.<domain>` и сравнивает с ожидаемыми значениями.
/// Возвращает Err ТОЛЬКО при сбое самого резолва (сеть/NXDOMAIN/битый адрес резолвера).
pub(crate) async fn check_txt_records(
    domain: &str,
    txt_records: &[TxtRecord],
    resolver_addr: &str,
    accept_invalid_certs: bool,
) -> anyhow::Result<DnsCheckOutcome>
```

- Внутри: `dns_check::lookup_txt_values(...)`, вычисление `missing` = ожидаемые, которых
  нет среди `found`; `ok = missing.is_empty()`.
- `issue_order` **переиспользует** этот хелпер для своего precheck (defense-in-depth):
  на `Err` — прежняя ошибка «DNS lookup failed…»; на `!ok` — прежнее детальное сообщение
  expected / published / missing. Поведение выпуска не меняется.

### Новый эндпоинт

`POST /api/acme-client/orders/<id>/check-dns` — guard `AuthenticatedPrivileged`.

- Грузит заказ, берёт `resolver_addr` = `settings.get_acme_dns_resolver()`,
  `accept_invalid_certs` = `settings.get_acme_accept_invalid_certs()`.
- Вызывает `check_txt_records(&order.domain, &order.txt_records, …)`.
- **Не меняет статус заказа. Не обращается к CA.**
- Ответ `200` с телом `DnsCheckResponse { ok, expected, found, missing, error }`:
  - На `Ok(outcome)` → `ok/expected/found/missing` из outcome, `error = None`.
  - На `Err(e)` → `ok=false`, `error=Some(строка)`, `expected` = значения из заказа,
    `found=[]`, `missing` = все ожидаемые. (НЕ 500 — чтобы фронт показал причину в модалке.)
- Зарегистрировать роут там же, где остальные `acme-client` роуты (mount list + openapi).

## Frontend

### Типы / API / store

- `types/AcmeClient.ts`: `DnsCheckResult { ok: boolean; expected: string[]; found: string[]; missing: string[]; error: string | null }`.
- `api/acmeClient.ts` (или где методы клиента): `checkDns(orderId): Promise<DnsCheckResult>`.
- `stores/acmeClient.ts`: action `checkDns(orderId)` — вызывает api, возвращает результат,
  выставляет `store.error` на сетевой сбой как в остальных экшенах. Не трогает `store.loading`
  выпуска (использовать отдельный флаг во фронте компонента для «проверка идёт»).

### Модалка (`AcmeClientTab.vue`)

Заменить одиночный submit на кастомный `#footer` slot `BaseModal` (`:hideFooter="false"`,
слот `footer`) с двумя кнопками:

- **Проверить DNS** — `severity="secondary"`, всегда активна (кроме времени самой проверки),
  `@click="runDnsCheck"`.
- **Запустить выпуск** — primary, `:disabled="!dnsOk || store.loading"`, `@click="checkAndIssue"`.
- Кнопка Cancel/закрытие — как раньше (через тот же слот либо оставить `@cancel`).

Эфемерное состояние компонента:

- `dnsOk: Ref<boolean>` — гейт.
- `dnsChecking: Ref<boolean>` — идёт проверка.
- `dnsResult: Ref<DnsCheckResult | null>` — для отображения.

Сброс `dnsOk=false`, `dnsResult=null` в: `openExistingTxtModal`, `submitNewOrder` (при показе
записей), `closeTxtModal`.

`runDnsCheck`:
```
dnsChecking = true
try { const r = await store.checkDns(currentOrderId); dnsResult = r; dnsOk = r.ok }
finally { dnsChecking = false }
```

Отображение результата под подсказкой:
- `dnsResult.ok` → зелёный блок `.vt-success`: «Обе записи видны в DNS — можно запускать выпуск».
- `!ok && error` → `.vt-error`: текст `error`.
- `!ok && !error` → `.vt-error` с разбивкой expected / published(found или «нет записей») / missing.

Новые i18n-ключи (EN + ES) в namespace `le`:
`checkDns`, `startIssue`, `dnsChecking`, `dnsOk`, `dnsMissingSome`, `dnsFoundNone`.

## Поток пользователя

New Order → показ TXT → правка зоны (bump serial, reload) → **Проверить DNS** (повторяемо) →
как только `ok` → активируется **Запустить выпуск** → выпуск (`set_ready`→poll→finalize).

## Тесты

- Backend: unit на `check_txt_records` — сборка `missing`/`ok` из наборов expected/found
  (без реальной сети; при необходимости выделить чистую функцию сравнения
  `evaluate_txt(expected, found) -> (missing, ok)` и покрыть её).
- Frontend: `vue-tsc` type-check зелёный.

## Совместимость

- Существующий `issue` эндпоинт и его precheck сохраняются без изменений семантики.
- Новый эндпоинт аддитивен; старые клиенты не ломаются.
