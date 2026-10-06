# Report: импорт CA по http(s)-URL

- **Дата:** 2026-10-06
- **Профиль:** business-feature
- **Статус:** Done

## Задача

В разделе Certificate Authorities импорт CA доступен только через модалку с
загрузкой файлов (сертификат + опционально приватный ключ). Добавить возможность
импорта по прямой http(s)-ссылке — тот же сценарий, но исходные файлы
скачивает сервер.

## Решение

**Бэкенд.** Новый эндпоинт `POST /api/certificates/ca/import-url` (JSON-тело),
права те же, что у файлового импорта — гард `AuthenticatedLocalAdmin`:

```json
{ "ca_cert_url": "https://host/ca.pem", "ca_key_url": "https://host/ca.key", "name": "Optional CN" }
```

- `fetch_url_limited()` — скачивание через `reqwest` (уже был в зависимостях):
  только схемы http/https, connect timeout 10с, общий таймаут 30с, до 5
  редиректов, лимит тела **10 МиБ** (по Content-Length и фактически при
  чтении чанками — чтобы не переполнить память ложным заголовком).
- Общая логика парсинга/сохранения/аудита вынесена из `import_ca` в хелпер
  `persist_imported_ca()` — оба пути (файл и URL) ведут себя одинаково: PEM
  или DER, CN из поля `name` либо из subject сертификата, тип CA — TLS,
  `is_imported = true`, аудит-событие `ImportCa`.
- Скачивание приватного ключа по URL опционально, как и файл в модалке.

**Фронт.** В `ImportCaDialog.vue` добавлен переключатель источника
(SelectButton «Из файла / Из URL»): в режиме URL — два текстовых поля
(сертификат — обязателен, ключ — опционален) с клиентской валидацией схемы
http(s). Поле имени (CN override) общее для обоих режимов. Стэк вызовов:
`stores/cas.ts importCaUrl()` → `api/cas.ts` → новый эндпоинт.

## Изменённые файлы

| Файл | Что |
|---|---|
| `backend/src/data/api.rs` | структура `ImportCaUrlRequest` |
| `backend/src/api.rs` | хендлер `import_ca_url`, `fetch_url_limited` + статический HTTP-клиент, рефакторинг `import_ca` → `persist_imported_ca` |
| `backend/src/lib.rs` | регистрация маршрута в трёх mount-блоках (prod + оба test) |
| `frontend/src/types/CA.ts` | интерфейс `CAImportUrlRequest` |
| `frontend/src/api/cas.ts` | `importCaUrl()` |
| `frontend/src/stores/cas.ts` | действие `importCaUrl()` |
| `frontend/src/components/dialogs/ImportCaDialog.vue` | переключатель Файл/URL, поля URL, валидация |
| `frontend/src/locales/en.json`, `es.json` | ключи `importCa.source*`, `caCertUrl`, `caKeyUrl`, `error*` |
| `backend/tests/api/api_test_functionality.rs` | 4 новых теста |

## Validation

- Новые интеграционные тесты: 4/4 — успех импорта с локального HTTP-сервера
  (сертификат + ключ, проверка `is_imported`/`has_private_key`), отказ `ftp://`,
  отказ при Content-Length > лимита, 403 для не-админа
- `cargo check` / `cargo clippy --all-targets` — чисто (2 предсуществующих
  warning в `integration_tests` не связаны с изменением)
- frontend: `vue-tsc` + `vite build` + vitest 36/36 — зелёные

## Ограничения (зафиксировано осознанно)

1. SSRF-поверхность: эндпоинт доступен только локальному админу (тот, кто и так
   управляет CA), схемы ограничены http/https, редиректы ≤5, таймауты и лимит
   размера выставлены. Проверки приватных диапазонов IP не делаются — админ и
   так имеет право указать внутренний URL.
2. Импорт по URL, как и файловый, создаёт CA типа TLS; SSH-CA по URL не
   импортируется (паритет с существующим поведением).
3. Соответствие ключа и сертификата не проверяется (паритет с файловым
   импортом); неконсистентная пара всплывёт при первой выдаче сертификата.
4. Ключ по URL проходит через память сервера в открытом виде — ожидаемо
   использовать https или доверенную внутреннюю сеть.
