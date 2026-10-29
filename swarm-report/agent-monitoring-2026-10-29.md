# Report: мониторинг агентов — heartbeat + дашборд «Агенты»

- **Дата:** 2026-10-29
- **Профиль:** business-feature
- **Релиз:** агент — [agent-v0.8.0](https://github.com/vasyakrg/VaulTLS/releases/tag/agent-v0.8.0); сервер/панель — образ из main (сервер 1.3.0, тег GitHub-релиза не ставился)
- **Статус:** Done

## Задача

Агенты ходят на сервер только за реконсиляцией. Собирать с них статус
(версия, ошибки последнего прохода, когда приходили) и показывать отдельным
дашбордом в панели, доступным всем пользователям на просмотр.

## Решение

**Транспорт:** новый `POST /api/agents/heartbeat` от агента (аутентификация —
сервисный токен, как у reconcile) + `GET /api/agents` для панели (люди всех
ролей; сервисным токенам запрещено). Heartbeat не аудируется (прецедент:
обмен `/auth/token` тоже нет).

**Идентичность:** пара (сервисный аккаунт из токена, agent_id). agent_id —
UUID, генерируется агентом в `/etc/ssl/vaultls/agent-id`; переопределяется
конфигом `heartbeat.agent_id` (для подов — в helm-chart-agent по умолчанию
имя релиза, иначе каждый рестарт пода выглядел бы новым агентом). Один
сервисный аккаунт на нескольких хостах = несколько строк (это правильно).

**Агент:** тикер heartbeat (default 5m, `0` — выключить, минимум 30s) +
отправка сразу после каждого reconcile-прохода и на старте. Снимок состояния
по доменам копится в потокобезопасном `internal/status`-трекере, который
`Reconciler` заполняет на каждой точке выхода `Domain()` (defer по named
return, стадия ошибки — `select`/`download`/`reload`/…). Отправка — новый
`vaultls.Client.PostJSON` (кэш токена, один re-auth на 401, без ретраев —
следующий тик всё донесёт). Сбой heartbeat — только warn в лог, никогда не
влияет на deploy.

**Сервер:** миграция `19-agents` (таблица `agents`, upsert по
`UNIQUE(account_id, agent_uuid)`, `first_seen` от первой встречи, `last_seen`
и `ip` — серверные). Сводный статус (`ok|error`), счётчик ошибок и ближайший
expiry считаются на сервере из отчёта, а не берутся у агента на слово.
«Offline» — производное: `now - last_seen > max(3×interval, 15 минут)`
(интервал агент сообщает). Ретеншн: не виденные 30 дней удаляются попутно с
входящими heartbeat. `GET /api/agents` джойнит имя аккаунта и логин владельца.

**Фронтенд:** новый всегда видимый таб «Агенты» (`/agents`): таблица
(host, аккаунт+владелец, версия, статус-Tag ok/error/offline, домены,
ближайший expiry, last seen относительным временем), поиск + фильтр статуса,
polling 30с (первый polling-компонент в проекте), детальный BaseModal с
run-фактами (платформа, schedule, интервал, IP, agent_id, последняя ошибка)
и таблицей доменов (destination, serial, expiry, last check, stage ошибки).
Локали en/es/fr; относительное время — локальная утилита (dayjs в проекте нет).

## Изменённые файлы

| Файл | Что |
|---|---|
| `backend/migrations/19-agents/{up,down}.sql` | таблица `agents` + индекс |
| `backend/src/data/api.rs` | DTO `AgentHeartbeatRequest`, `AgentDomainReport` |
| `backend/src/data/objects.rs` | `AgentHeartbeatIn`, `AgentRecord`, `AgentStatusRow` |
| `backend/src/db.rs` | `upsert_agent_heartbeat`, `list_agents` (JOIN), `prune_stale_agents`, `agent_from_row` |
| `backend/src/agents.rs` | роуты heartbeat/list, `agent_online`, клампы строк, юнит-тесты порога |
| `backend/src/lib.rs` | `mod agents`, роуты во всех трёх списках |
| `backend/tests/api/api_test_agents.rs` | 4 интеграционных теста (upsert/листинг/guard-матрица/валидация) |
| `api-client/internal/status/` | трекер снимка по доменам + тесты |
| `api-client/internal/vaultls/client.go` | `PostJSON` + 3 теста (Bearer/тело, re-auth на 401, не-2xx) |
| `api-client/internal/heartbeat/` | Reporter: payload, UUID-файл, override, Run-цикл + тесты |
| `api-client/internal/reconcile/reconcile.go` | трекер в `New`, defer-observe со stage по всем точкам выхода |
| `api-client/internal/reconcile/status_test.go` | ok / cheap-skip / error+stage |
| `api-client/internal/config/{config,load}.go` | секция `heartbeat` (interval/agent_id) + 4 теста |
| `api-client/internal/app/app.go` | трекер, `sendHeartbeat` после проходов, фоновый тикер |
| `api-client/internal/wizard/wizard.go` | heartbeat: 5m в рендер конфига |
| `api-client/packaging/config.example.yaml` | секция heartbeat с комментарием |
| `api-client/README.md` | `heartbeat.*` в справочнике полей |
| `helm-chart-agent/{values.yaml,templates/configmap.yaml}` | `heartbeat.interval`, `agentId` (default: имя релиза) |
| `frontend/src/types/Agent.ts`, `api/agents.ts`, `stores/agents.ts` | типы, API, merge-and-prune стор |
| `frontend/src/components/AgentsTab.vue` | дашборд: таблица, фильтры, polling 30с, детальный модал |
| `frontend/src/router/router.ts`, `components/Sidebar.vue` | маршрут + всегда видимый пункт (pi-server) |
| `frontend/src/locales/{en,es,fr}.json` | `sidebar.agents` + секция `agents.*` |

## Validation

- Бэкенд: `cargo check` чисто; `cargo test --test integration_tests` — все
  зелёные (включая 4 новых); юнит-тесты `agent_online` (порог 3×/15 минут)
- Агент: `go build ./...`, `go vet ./...`, `gofmt -l .` чисто; `go test ./...`
  — все пакеты зелёные (status, heartbeat, PostJSON, reconcile-трекер, конфиг)
- Фронтенд: `npm run build` (type-check + vite) зелёный; `npm run test:unit` —
  36 тестов зелёные
- Сквозной smoke: локальный rocket (setup → логин → сервисный аккаунт) +
  `vaultls-agent check` против него → `GET /api/agents` показывает агента
  (hostname, версия, os/arch, status=error со stage select по домену,
  account_name/owner_login, online=true, ip); сервисный токен на GET — 403;
  агент без серта завершается exit 0 (heartbeat не роняет check)

## Ограничения (зафиксировано осознанно)

1. Хранится только последний снимок (domains_json) — без истории/временных
   рядов; при необходимости — отдельная фича.
2. Новый service-scope для heartbeat не вводился: любой сервисный токен
   репортит под своим аккаунтом.
3. Clock-skew в offline-детекте не учитывается — тройной интервал его покрывает.
4. helm-chart-agent при replicas > 1: поды делят один agent_id (last write
   wins) — чарт рассчитан на один реплику, задокументировано в values.
5. e2e-тесты фронтенда (playwright) не добавлены — таблица покрыта юнитами и
   smoke; ids для e2e (`AgentStatus-<id>` и др.) заложены.
