# Report: agent — подкоманда reload для отладки reload-команд

- **Дата:** 2026-10-29
- **Профиль:** business-feature
- **Релиз:** [agent-v0.7.0](https://github.com/vasyakrg/VaulTLS/releases/tag/agent-v0.7.0)
- **Статус:** Done

## Задача

`domains[].reload` и `ca_trust.update_command` выполняются только когда
сертификат (или trust store) реально изменился. Для отладки скриптов внутри
этих команд нужен способ дернуть их по требованию — без обновления сертификатов,
без обращения к серверу и без порчи state.

## Решение

Новая подкоманда `vaultls-agent reload`:

```sh
vaultls-agent reload                       # reload-команды всех доменов
vaultls-agent reload -d haproxy.internal   # один домен (флаг повторяемый)
vaultls-agent reload --ca                  # + ca_trust.update_command
```

Свойства:

- **Без сервера и без state**: читает только конфиг, запускает команды через
  тот же `sh -c`, reconcile-логика не задействована.
- **Живой вывод**: вывод команды стримится прямо в терминал (stdout/stderr
  пробрасываются), а не глотается как в reconcile-пути (`reloader.RunAttached`).
- **Изоляция сбоев**: упавшая команда не останавливает остальные; итог —
  `N of M reload command(s) failed`, exit code 1.
- **Опечатка — ошибка**: неизвестный `--domain` → ошибка со списком
  сконфигурированных имён, exit 1 (ничего не запускается).
- **Общее имя**: несколько конфиг-записей с одним `name` (разные серты/пути) —
  по `--domain` выполняются все записи с этим именем.
- `--ca` без заданного `update_command` — warning, не ошибка. `ca_trust.enabled`
  при явном `--ca` не проверяется: флаг сам по себе является opt-in.
- Домены без `reload`-команды пропускаются с info-сообщением (в конфиге для
  file-таргетов reload обязателен, но k8s-таргеты его не требуют).

## Изменённые файлы

| Файл | Что |
|---|---|
| `api-client/internal/reloader/reloader.go` | `RunAttached` — запуск с пробросом вывода в writers |
| `api-client/internal/app/reload.go` | `Reload`/`runReload`/`selectReloadDomains` — логика подкоманды |
| `api-client/cmd/vaultls-agent/reload.go` | флаги `-d/--domain` (повторяемый), `--ca`, `--config` |
| `api-client/cmd/vaultls-agent/main.go` | регистрация подкоманды, usage |
| `api-client/internal/reloader/reloader_test.go` | 3 теста: оба потока, вывод при сбое, no-op |
| `api-client/internal/app/reload_test.go` | 7 тестов: все домены, фильтр, общее имя, неизвестный домен, `--ca`, warning, изоляция сбоев |
| `api-client/README.md` | строка в таблице команд + раздел «Debugging reload commands» |

## Validation

- `go build ./...`, `go vet ./...`, `go test ./...` — все пакеты зелёные
- `gofmt -l .` — чисто
- Smoke-тест бинарника на временной конфигурации: оба домена выполняются,
  вывод стримится, сбойный `exit 3` даёт `1 of 2 failed` и exit 1; `-d` фильтрует;
  неизвестный домен — ошибка со списком имён; `--ca` выполняет update_command;
  usage обновлён

## Ограничения (зафиксировано осознанно)

1. Выборка только по `name`: домены, заданные голым `cert_id` (без имени),
   по `--domain` не выбираются — выполняются только в режиме «все».
2. Лог-сообщения подкоманды идут через настраиваемый логгер (stderr или
   `log.file` из конфига), а вывод самих команд — всегда в терминал.
3. Reconcile-путь (`reloader.Run`) по-прежнему глотает вывод успешных команд —
   осознанно не трогали; для отладки есть `reload`.
