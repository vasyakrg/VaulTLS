# VaulTLS: Prometheus-метрики и алертинг по срокам/проблемам сертификатов

Дата: 2026-07-01
Область: `backend/src/metrics.rs` (новый), `backend/src/lib.rs` (mount + module), `backend/src/auth/` (guard), `docs/observability.md` (новый), `helm-chart/` (env + аннотации).

## Проблема

VaulTLS не отдаёт наблюдаемость: сроки истечения сертов/CA и проблемы ACME-продления (застрявшие/провалившиеся заказы) нигде не видны для мониторинга. Почта как канал уведомлений не используется. Нужен pull-эндпоинт метрик для Prometheus и готовые правила алертинга.

## Решения (зафиксированы)

- Exposition: свой Prometheus text-формат (0.0.4), считается на каждый scrape из БД. Без крейта `prometheus`.
- Доступ: опциональный Bearer-токен `VAULTLS_METRICS_TOKEN` (не задан → открыт).
- Гранулярность: per-cert / per-CA gauge + агрегаты.

## Не входит в объём (YAGNI)

- Крейт `prometheus`, гистограммы, латентности HTTP, pushgateway.
- Метрики по SSH-принципалам/пользователям.
- Пороговые «expiring_7d/30d» как отдельные метрики (считаются правилами Prometheus над `expiry_timestamp`).

## Метрики

Все — `gauge`. Timestamps в unix-**секундах** (`valid_until` в БД — миллисекунды, делим на 1000). `HELP`/`TYPE` строки на каждую метрику.

**build info**
- `vaultls_build_info{version="v1.2.3"} 1` — version из `crate::constants::VAULTLS_VERSION`.

**Сертификаты (leaf, `user_certificates`)** — источник `db.get_user_certs(None, None, None)`.
- `vaultls_certificate_expiry_timestamp_seconds{id,cn,type,issuer}` — только НЕ revoked (`revoked_at IS NULL`). `type` ∈ {`tls_client`,`tls_server`,`ssh_client`,`ssh_server`} из `CertificateType`. `issuer`:
  - `acme_provider_id` задан → `acme:<provider_name>`;
  - иначе `ca_id` задан → `ca:<ca_name>`;
  - иначе → `imported`.
  - `cn` — CN из `Name` серта.
- Агрегаты:
  - `vaultls_certificates_total{type}` — счётчик по типу (все, включая revoked).
  - `vaultls_certificates_expired_total` — не-revoked с `valid_until < now`.
  - `vaultls_certificates_revoked_total` — с `revoked_at IS NOT NULL`.

**CA (`ca_certificates`)** — источник `db.get_all_ca()`.
- `vaultls_ca_expiry_timestamp_seconds{id,cn,type}` — `type` из `CAType`; `cn` из `Name`.

**ACME-клиент (проблемы/in-flight)** — источник `db.get_all_acme_client_orders()`.
- `vaultls_acme_order_created_timestamp_seconds{id,domain,status}` — только заказы со статусом ≠ `valid` (т.е. `pending_dns`/`ready`/`failed`/`expired`). Значение = `created_on/1000`. Позволяет алерт «висит >1ч».
- `vaultls_acme_orders_total{status}` — счётчик заказов по статусу.

**Кардинальность:** лейблы `id`+`cn`/`domain` на серт/заказ; для масштаба VaulTLS (десятки-сотни) приемлемо.

## Формат и экранирование

Отдельная чистая функция рендера, покрытая тестами. Экранирование значений лейблов по спецификации Prometheus: `\` → `\\`, `"` → `\"`, перевод строки → `\n`. Числа — целые (секунды). Имя метрики + `{k="v",...} <value>\n`. `HELP`/`TYPE` печатаются один раз перед серией.

Пример фрагмента:
```
# HELP vaultls_certificate_expiry_timestamp_seconds Leaf certificate notAfter as unix seconds.
# TYPE vaultls_certificate_expiry_timestamp_seconds gauge
vaultls_certificate_expiry_timestamp_seconds{id="7",cn="novotelecom.ru",type="tls_server",issuer="acme:Let's Encrypt"} 1730419200
```

## Эндпоинт и доступ

**Route** `GET /metrics` → `(ContentType(text/plain; version=0.0.4), String)`. Монтируется обычным `routes![metrics]` (не `openapi_get_routes!`, т.к. не JSON-API) на `/` в КАЖДОМ rocket-build в `lib.rs` (их несколько — все).

**Guard `MetricsAuth`** (`FromRequest`):
- читает env `VAULTLS_METRICS_TOKEN` напрямую через `std::env::var` (как `VAULTLS_ACME_DNS_RESOLVER`); trim, пустая строка = не задан;
- если пусто/не задан → `Outcome::Success` (открыт);
- если задан → сверяет заголовок `Authorization: Bearer <token>` (константное сравнение); несовпадение/отсутствие → `Outcome::Error(Unauthorized)`.
- Паттерн Bearer-парсинга — как в `auth/session_auth.rs:126-132`.

## Документация `docs/observability.md`

1. Таблица метрик (имя, тип, лейблы, смысл).
2. `scrape_config` для Prometheus (job `vaultls`, `metrics_path: /metrics`, `authorization: { type: Bearer, credentials: <token> }`, интервал 60s).
3. Prometheus alert rules (группа `vaultls`):
   - `CertExpiringSoon` — `vaultls_certificate_expiry_timestamp_seconds - time() < 30*86400` `for: 1h`, severity warning.
   - `CertExpiringCritical` — `< 7*86400`, severity critical.
   - `CertExpired` — `vaultls_certificate_expiry_timestamp_seconds - time() < 0`, critical.
   - `CAExpiringSoon` — то же по `vaultls_ca_expiry_timestamp_seconds`, `< 30*86400`.
   - `AcmeOrderStuck` — `time() - vaultls_acme_order_created_timestamp_seconds > 3600` (метрика присутствует только для не-valid), `for: 30m`, warning; в аннотации domain/status.
   - `VaultlsDown` — `up{job="vaultls"} == 0` `for: 5m`, critical.
4. Пример Alertmanager `route`/`receiver` с группировкой по `severity` и маршрутизацией critical в отдельный receiver.

## Helm

- `values.yaml`: `config.metrics.token` (в secret) + `metrics.podAnnotations` (по умолчанию `prometheus.io/scrape: "true"`, `prometheus.io/path: "/metrics"`, `prometheus.io/port: "<port>"`).
- `deployment.yaml`: проброс `VAULTLS_METRICS_TOKEN` из secret, если задан; аннотации на pod-шаблон.

## Тесты

- Unit: форматтер — экранирование CN с `"`/`\`/newline; корректный вывод per-cert строки и агрегата; пустой набор.
- Unit: `MetricsAuth` — токен не задан (Success), задан+верный Bearer (Success), задан+неверный/без заголовка (Unauthorized).
- Ручная проверка: `curl -H "Authorization: Bearer …" http://host/metrics` на проде; scrape виден в Prometheus; alert rules валидны (`promtool check rules`).

## Совместимость / риски

- Аддитивно: новый эндпоинт и модуль, существующие роуты не трогаем.
- При отсутствии токена эндпоинт открыт — в доке явно предупредить закрывать сетевой политикой.
- Метрики читают БД на каждый scrape (несколько SELECT); при интервале 60s нагрузка пренебрежимо мала.
