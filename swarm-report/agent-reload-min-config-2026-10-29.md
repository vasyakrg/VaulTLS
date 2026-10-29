# Report: agent — reload на минимальном конфиге (фикс agent-v0.7.0)

- **Дата:** 2026-10-29
- **Профиль:** bugfix
- **Релиз:** [agent-v0.7.1](https://github.com/vasyakrg/VaulTLS/releases/tag/agent-v0.7.1)
- **Статус:** Done

## Задача

`vaultls-agent reload` падал с `server.client_id and server.secret are
required` на конфиге без блока `server`. Причина: подкоманда грузила конфиг
через `config.Load` с полной валидацией для reconcile, хотя сервер не дергает
вообще.

## Решение

Разделён пути загрузки в `internal/config`:

- `Load(path)` — как раньше: чтение + env-подстановка + defaults + валидация
  (все существующие пути — `run`/`check`/`setup` — не изменились);
- `LoadUnvalidated(path)` — то же без семантической валидации; использует только
  `reload`-подкоманда.

Итоговое поведение: `reload` читает только `domains[].name`,
`domains[].reload` и `ca_trust.update_command` — минимального конфига без
`server` достаточно. Битый YAML по-прежнему ошибка (громко, для обоих путей);
defaults применяются (в т.ч. автоподстановка `ca_trust.update_command`, чтобы
`--ca` запускал ровно то же, что запускал бы reconcile).

## Изменённые файлы

| Файл | Что |
|---|---|
| `api-client/internal/config/load.go` | `loadFile` extracted; `LoadUnvalidated` |
| `api-client/internal/app/reload.go` | `Reload` использует `LoadUnvalidated` |
| `api-client/internal/config/load_test.go` | 2 теста: минимальный конфиг проходит / `Load` по-прежнему валидирует, битый YAML — ошибка |
| `api-client/internal/app/reload_test.go` | регрессионный тест: конфиг без `server`-блока работает |
| `api-client/README.md` | абзац о минимальном конфиге в «Debugging reload commands» |

## Validation

- `go build ./...`, `go vet ./...`, `go test ./...` (config/app/reloader) — зелёные
- `gofmt -l .` — чисто
- Smoke: `reload` на конфиге из трёх строк (`domains: name + reload`) — exit 0,
  команда выполняется; `reload` на битом YAML — `parse config: …`, exit 1

## Ограничения (зафиксировано осознанно)

1. `reload` не сообщает о невалидности конфига для reconcile (например,
   дубликаты destinations) — это работа `check`, а не отладочной подкоманды.
2. defaults по-прежнему применяются, поэтому включённый `ca_trust.enabled` без
   распознанного trust store даст ошибку загрузки и у `reload` тоже — конфиг
   сломан для агента в целом.
