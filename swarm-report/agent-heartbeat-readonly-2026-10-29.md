# Report: agent — heartbeat живёт на read-only /etc/ssl/vaultls (фикс agent-v0.8.0)

- **Дата:** 2026-10-29
- **Профиль:** bugfix
- **Релиз:** [agent-v0.8.1](https://github.com/vasyakrg/VaulTLS/releases/tag/agent-v0.8.1)
- **Статус:** Done

## Задача

В контейнере с read-only `/etc/ssl/vaultls` и конфигом без
`heartbeat.agent_id` (под с конфигом до обновления chart'а) heartbeat
полностью умирал: `mkdir /etc/ssl/vaultls: read-only file system` — на каждом
отправке, статуса на дашборде нет.

## Решение

1. **Fallback в памяти:** если файл agent-id недоступен для записи — id
   генерируется и держится в памяти процесса, отправки продолжаются. Warning
   пишется однократно (`noFile`-флаг: без повторных попыток mkdir и без
   «мигания» id между файлом и памятью, если директория вдруг станет
   доступной). Деградация осознанная: строка дашборда на рестарт процесса;
   стабильность даёт `heartbeat.agent_id` (обновлённый helm-chart-agent
   проставляет его именем релиза).
2. **Один Reporter на процесс:** ранее отправка после reconcile-прохода и
   тикер создавали по своему Reporter — в file-less сценарии это дало бы два
   разных in-memory id у одного агента. Теперь общий инстанс, идентичность
   детерминирована; конкурентный доступ защищён мьютексом.

## Изменённые файлы

| Файл | Что |
|---|---|
| `api-client/internal/heartbeat/heartbeat.go` | fallback + `generateUUID`/`writeID`-хелперы, мьютекс, логгер в конструкторе |
| `api-client/internal/app/app.go` | `newHeartbeatReporter` — единый Reporter для пост-проходов и тикера |
| `api-client/internal/heartbeat/heartbeat_test.go` | 2 теста read-only (стабильность id в процессе, warning однократно, новый процесс — новый id) |
| `api-client/README.md` | описание fallback в справочнике `heartbeat.agent_id` |

## Validation

- `go build/vet/test ./...` — зелёные; `gofmt -l .` чисто
- Smoke: конфиг без `agent_id` на недоступной для записи директории — один
  warn про in-memory id, heartbeat продолжается (ошибка только до мёртвого
  URL), exit 0

## Ограничения (зафиксировано осознанно)

1. Read-only без `agent_id` = новая строка дашборда на каждый рестарт пода;
   сервер вычистит их через 30 дней, но правильное решение — задать
   `heartbeat.agent_id` (chart уже делает) или примонтировать writable-путь.
2. Тесты fallback пропускаются под root (root обходит права каталогов).
