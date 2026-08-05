# Report: agent — формат `nginx` и расширения файлов сертификата

- **Дата:** 2026-08-05
- **Профиль:** business-feature
- **Релиз:** [agent-v0.5.0](https://github.com/vasyakrg/VaulTLS/releases/tag/agent-v0.5.0) (предполагаемый)
- **Статус:** Done

## Задача

Расширения выходных файлов шли в коде жёстко — всегда `.pem`. Нужно:

- формат `haproxy` — объединённый файл с расширением `.pem` (как и раньше);
- формат `nginx` — приватный ключ с расширением `.key`, остальные файлы (fullchain/cert/chain) — `.crt`.

Заодно выяснилось: README уже описывал такое поведение (`.crt`/`.key`), но код ему не соответствовал — везде писался `.pem`. Т.е. это ещё и устранение рассинхронизации docs↔code.

## Решение

Формат, который раньше назывался `pem` (split-формат: fullchain/cert/chain/privkey),
переименован в `nginx`. Старое значение `pem` оставлено как **алиас** — старые конфиги
работают без правок. Расширения файлов сменены с `.pem` на `.crt` (сертификаты) и `.key`
(приватный ключ) — именно это разделение ожидает nginx (`ssl_certificate` / `ssl_certificate_key`).

| Формат | Расширения |
|---|---|
| `nginx` (алиас `pem`) | fullchain/cert/chain → `.crt`, privkey → `.key` |
| `haproxy` | объединённый fullchain+key → `.pem` |

Дефолтный формат при незаданном `formats:` — теперь `nginx`.

Схема именования с `basename`:

| Дефолт | `basename: example` |
|---|---|
| `fullchain.crt` | `example.crt` |
| `cert.crt` | `example-cert.crt` |
| `chain.crt` | `example-chain.crt` |
| `privkey.key` | `example-key.key` |
| `haproxy.pem` | `example-haproxy.pem` |

Права доступа не изменились: приватный ключ и haproxy-файл — `0600`, остальные — по `mode`.

### Рефакторинг именования

Прежний монолитный `FileNames` (5 полей) заменён на две сущности, отражающие, что split-формат
и haproxy — это разные файлы с разными правилами расширений:

- `SplitFileNames` + `Domain.SplitFileNames()` — имена для `nginx`/`pem` (`.crt`/`.key`);
- `Domain.HaproxyFileName()` — имя объединённого haproxy-бандла (`.pem`).

## Изменённые файлы

| Файл | Что |
|---|---|
| `api-client/internal/config/config.go` | `SplitFileNames`/`SplitFileNames()`/`HaproxyFileName()` вместо `FileNames`/`FileNames()`; расширения `.crt`/`.key` |
| `api-client/internal/config/load.go` | дефолт `nginx`; валидация принимает `nginx`/`pem`/`haproxy` |
| `api-client/internal/reconcile/write.go` | `case "nginx","pem"` (split) и `case "haproxy"`; имя через новые методы |
| `api-client/internal/config/load_test.go` | обновлены assertions имён и дефолтного формата |
| `api-client/internal/reconcile/reconcile_test.go` | обновлены assertions имён; `nginx` в хелпере; добавлен `TestReconcilePEMAliasMatchesNginx` |
| `api-client/internal/pki/pki_test.go` | тексты сообщений (без `.pem`-литералов) |
| `api-client/internal/app/app_test.go` | `nginx` в тестовом конфиге |
| `api-client/internal/wizard/wizard.go` | генерирует `nginx` |
| `api-client/README.md` | capabilities, справочник поля, таблицы форматов, раздел basename, примеры, миграционное примечание |
| `api-client/packaging/config.example.yaml` | комментарий про имена + `formats: [nginx, haproxy]` |

## Validation

- `go build ./...`, `go vet ./...` — чисто
- `go test ./...` — все пакеты зелёные (включая новый тест-регрессию на алиас `pem`)
- `gofmt -l .` — чисто
- `grep` по дереву: ссылок на старые `FileNames`/`defaultFileNames`/`.FileNames()` не осталось

## Обратная совместимость и миграция

1. **Алиас `pem`.** Конфиги со значением `formats: [pem]` по-прежнему валидны и дают тот же
   split-формат, что и `nginx`. Менять конфиг необязательно.
2. **Смена расширений на диске.** До этой версии split-формат писал `fullchain.pem`/`cert.pem`/
   `chain.pem`/`privkey.pem`; теперь это `fullchain.crt`/`cert.crt`/`chain.crt`/`privkey.key`.
   После обновления агента нужно: указать в nginx-конфиге новые имена (или задать `basename`),
   перечитать конфиг, и удалить старые `*.pem` файлы вручную — агент их не чистит (как и при
   смене `basename`). Задокументировано в README в блоке «Migration from `pem`».
3. **haproxy** поведение не изменилось — объединённый `.pem`.
