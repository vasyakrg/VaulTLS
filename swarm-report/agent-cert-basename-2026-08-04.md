# Report: agent — basename override для имён файлов сертификата

- **Дата:** 2026-08-04
- **Профиль:** business-feature
- **Релиз:** [agent-v0.4.0](https://github.com/vasyakrg/VaulTLS/releases/tag/agent-v0.4.0)
- **Статус:** Done

## Задача

Дать возможность в конфиге домена переопределять имена выходных файлов сертификата.
Без ключа — прежнее поведение (`fullchain.pem`, `cert.pem`, …).

## Решение

Новое опциональное поле `domains[].basename`. Схема именования:

| Дефолт | `basename: example` |
|---|---|
| `fullchain.pem` | `example.pem` |
| `cert.pem` | `example-cert.pem` |
| `chain.pem` | `example-chain.pem` |
| `privkey.pem` | `example-key.pem` |
| `haproxy.pem` | `example-haproxy.pem` |

Права доступа не изменились: приватный ключ и haproxy-файл — `0600`, остальные — по `mode`.

Валидация: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. Значение конкатенируется с суффиксами и
джойнится на `out_dir`, поэтому разделитель пути позволил бы выйти из директории, а ведущая
точка — затенить служебный `.vaultls-state.json`.

## Изменённые файлы

| Файл | Что |
|---|---|
| `api-client/internal/config/config.go` | поле `Basename`, тип `FileNames`, метод `Domain.FileNames()` |
| `api-client/internal/config/load.go` | `validateBasename` + вызов в `validate()` |
| `api-client/internal/reconcile/write.go` | запись через `d.FileNames()` вместо литералов |
| `api-client/internal/config/load_test.go` | 4 теста: валидные/невалидные basename, обе схемы имён |
| `api-client/internal/reconcile/reconcile_test.go` | `TestReconcileHonorsBasename` |
| `api-client/README.md` | справочник поля + раздел «Renaming output files» |
| `api-client/packaging/config.example.yaml` | закомментированный пример |

## Validation

- `go build ./...`, `go vet ./...`, `go test ./...` — все пакеты зелёные
- `gofmt -l .` — чисто (попутно отформатирован `reconcile_test.go`, расхождение было до правки)
- `make deb VERSION=0.4.0` локально — `vaultls-agent_0.4.0_amd64.deb`, `Version: 0.4.0`
- CI `agent-release` run 30899242023 — успешно, deb приложен к релизу

## Ограничения (зафиксировано осознанно)

1. Смена `basename` на живой инсталляции не удаляет файлы, записанные под прежним именем —
   чистка вручную. Задокументировано в README.
2. Несколько доменов в один `out_dir` по-прежнему запрещены валидатором. Это не обходится
   через `basename`: state-файл `.vaultls-state.json` один на директорию, второй домен затирал
   бы serial первого. Для сценария «несколько сертов в одну папку» нужна отдельная доработка
   `internal/store` (ключевание state по basename или cert_id).
