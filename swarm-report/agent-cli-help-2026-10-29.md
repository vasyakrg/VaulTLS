# Report: agent — `--help` и читаемый usage в CLI

- **Дата:** 2026-10-29
- **Профиль:** bugfix
- **Релиз:** [agent-v0.7.1](https://github.com/vasyakrg/VaulTLS/releases/tag/agent-v0.7.1)
- **Статус:** Done

## Задача

`vaultls-agent --help` отвечал `unknown command "--help"`. У подкоманд
`--help`/`-h` печатали флаги, но завершались с exit 2.

## Решение

- Топ-уровень: `help`, `--help`, `-h` → развёрнутый usage в stdout, exit 0.
  Usage теперь не просто перечень, а по строке на команду с описанием.
- Без аргументов — usage в stderr, exit 2 (как было); неизвестная команда —
  сообщение + usage, exit 2.
- Подкоманды (`run`/`setup`/`reload`, включая `check` через `run`):
  `flag.ErrHelp` → exit 0 вместо 2; сами флаги печатает flag-пакет.

## Изменённые файлы

| Файл | Что |
|---|---|
| `api-client/cmd/vaultls-agent/main.go` | константа `usage`, кейсы help/-h/--help, вывод usage при неизвестной команде |
| `api-client/cmd/vaultls-agent/run.go` | `flag.ErrHelp` → exit 0 |
| `api-client/cmd/vaultls-agent/setup.go` | то же |
| `api-client/cmd/vaultls-agent/reload.go` | то же |

## Validation

- `go build ./...`, `go vet ./...`, `go test ./...`, `gofmt -l .` — чисто
- Smoke бинарника: `--help`/`-h`/`help` → stdout, exit 0; без аргументов →
  stderr, exit 2; `reload --help`, `run --help`, `setup --help` → флаги,
  exit 0; `bogus` → `unknown command` + usage, exit 2

## Ограничения (зафиксировано осознанно)

1. `--help` подкоманд печатается flag-пакетом в stderr (стандартное поведение
   `flag.ContinueOnError`) — не переводился в stdout ради простоты.
2. `version --help` не обрабатывается отдельно: `version` игнорирует аргументы.
