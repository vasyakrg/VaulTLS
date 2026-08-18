# Report: agent — Kubernetes Secret target

- **Дата:** 2026-08-18
- **Профиль:** business-feature
- **Релиз:** [agent-v0.6.0](https://github.com/vasyakrg/VaulTLS/releases/tag/agent-v0.6.0)
- **Образ:** `ghcr.io/vasyakrg/vaultls-agent:0.6.0` (linux/amd64, 23.5 МБ)
- **Статус:** Done

## Задача

Дать кубу доступ к сертификатам VaulTLS: агент кладёт сертификаты в Secret'ы в ns=default,
дальше пользователь растаскивает их по namespace'ам политиками Kyverno и обновляет по мере
ротации сертов в default.

## Решение

`domains[].target: k8s` — второй таргет доставки рядом с файловым.

```yaml
domains:
  - name: "*.example.com"
    target: k8s
    k8s:
      namespace: default
      secret: wildcard-example-com
      include_ca: true
      labels:
        vaultls.io/replicate: "true"
```

Secret: тип `kubernetes.io/tls`, `tls.crt` = fullchain, `tls.key` = privkey, `ca.crt` = chain
(при `include_ca`). State деплоя (cert-id, serial, valid-until, last-check, last-renewal) —
в аннотациях `vaultls.io/*` самого Secret: у пода нет тома под `.vaultls-state.json`, а
перезапущенный агент обязан понимать, что ничего не изменилось.

Логика выбора серта, декода p12 и скипа по serial общая для обоих таргетов — разошлась только
доставка (интерфейс `target.Target`).

### Ключевые решения

| Решение | Почему |
|---|---|
| Свой REST-клиент вместо client-go | Тот же бинарь едет .deb'ом на ноды; client-go раздул бы его с 11 до ~50 МБ ради трёх глаголов на одном ресурсе. Токен SA перечитывается на каждый запрос — kubelet ротирует projected-токены. |
| JSON merge patch, а не полная запись | Патч трогает только свои ключи, поэтому лейблы и аннотации от других контроллеров (в т.ч. Kyverno) переживают ротацию. Поле `type` иммутабельно и не патчится. |
| Deployment, а не CronJob | У агента уже есть cron+jitter и экспортер; живой под = скрейпится `vaultls_cert_expiry_timestamp_seconds`. У CronJob метрики исчезают вместе с подом. |
| Файловые ключи на k8s-домене — ошибка, а не игнор | Конфиг с `out_dir` рядом с `target: k8s` описывает вывод, которого никогда не будет. |
| `include_ca: false` шлёт `"ca.crt": null` | Merge patch удаляет ключ, иначе протухшая цепочка осталась бы в Secret навсегда. |

## Изменённые файлы

| Файл | Что |
|---|---|
| `api-client/internal/k8s/client.go` | минимальный REST-клиент: in-cluster конфиг, get/create/merge-patch Secret |
| `api-client/internal/target/{target,file,k8s}.go` | интерфейс `Target` + фабрика; файловая запись переехала из `reconcile/write.go` |
| `api-client/internal/reconcile/reconcile.go` | работа через `Target`, метки метрик по `Describe()` |
| `api-client/internal/config/{config,load}.go` | поля `target`/`k8s`, раздельная валидация по таргетам, DNS-1123 для имён |
| `api-client/internal/app/app.go`, `cmd/.../run.go` | `app.Options`, флаг `--no-self-update` для контейнера |
| `api-client/Containerfile`, `Makefile` | distroless-образ, цель `make image` |
| `.github/workflows/agent-release.yml` | сборка и пуш образа в ghcr по тегу `agent-v*`, actions обновлены (checkout@v7, setup-go@v7, gh-release@v3, docker/*@v4,v7), починен кеш Go (`cache-dependency-path: api-client/go.sum`) |
| `helm-chart-agent/**` | чарт: Deployment, ConfigMap, Secret с кредами, SA, Role+RoleBinding на каждый целевой ns, Service, ServiceMonitor |
| `api-client/README.md`, `helm-chart-agent/README.md` | справочник таргета, RBAC, инструкция по Kyverno |

## RBAC

Role на каждый целевой namespace, ClusterRole нет. `create` вынесен отдельным правилом:
resourceNames его не сужает, потому что при авторизации объекта ещё не существует.
`get/update/patch` пришпилены к конкретным именам Secret'ов из `certificates[]`.

## Validation

- `go build`, `go vet`, `go test ./...` — зелёные; `gofmt -l` чисто
- новые тесты: create/patch Secret'а, удаление `ca.crt` при выключенном include_ca, round-trip
  state через аннотации, 404 = первый деплой, 403 = ошибка (а не «ничего не задеплоено»),
  e2e reconcile через фейковый API-сервер со скипом на втором проходе, 6 тестов валидации конфига
- `helm lint` + `helm template` — ок; отрендеренный config.yaml скормлен реальному загрузчику
  агента: единственная ошибка — ожидаемая «not running in a cluster»
- `make image VERSION=0.5.0` локально → 23.5 МБ, `vaultls-agent 0.5.0`
- CI run 32123388849 — успешно: deb в релизе, `docker pull ghcr.io/vasyakrg/vaultls-agent:0.6.0`
  проверен, отдаёт `vaultls-agent 0.6.0`

## Что осталось за агентом (сторона пользователя)

1. ClusterRole `kyverno:secrets:view` и `:manage` с лейблами
   `rbac.kyverno.io/aggregate-to-background-controller` — без них клонирование молча не работает.
2. `ClusterPolicy` с `cloneList` + `synchronize: true`, селектор по `vaultls.io/replicate: "true"`.
   Обновление source Secret'а агентом разъезжается по клонам само.
3. Потребители: ingress-контроллеры перечитывают Secret сами, поды с volumeMount получат новые
   файлы (~1 мин), но процесс внутри — нет. Нужен Reloader или рестарт.

Оба пункта расписаны в `helm-chart-agent/README.md`.

## Ограничение

Клоны наследуют аннотации `vaultls.io/*` — Kyverno копирует их вместе с данными. Безвредно
(агент читает их только из source), но если начнёт мешать — state вынесем в отдельный ConfigMap.
