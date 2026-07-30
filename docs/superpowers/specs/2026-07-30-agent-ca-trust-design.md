# vaultls-agent — установка корневых CA в системное доверенное хранилище (дизайн)

- Дата: 2026-07-30
- Профиль: business-feature
- Статус: утверждён к планированию
- Расположение в репозитории: `api-client/`

## 1. Назначение

`vaultls-agent` раскладывает TLS-серты на хост, но корневой сертификат VaulTLS
остаётся неизвестным системе: `curl`, `psql`, `openssl s_client` и любой другой
локальный клиент отвергают серты, выпущенные внутренним CA. Фича добавляет
агенту вторую обязанность — поддерживать корневые сертификаты VaulTLS в
системном доверенном хранилище (на Debian это `/usr/local/share/ca-certificates`
→ `update-ca-certificates` → `/etc/ssl/certs`).

По умолчанию **выключено**: агент не имеет права молча менять доверие хоста.

Вне границ: доверие на уровне отдельных приложений (JVM keystore, NSS-базы
Firefox/Chrome), доверие к SSH CA, ротация по событию из VaulTLS (только pull).

## 2. Источник данных

`GET /api/certificates/ca/bundle` — существующий эндпоинт бэкенда
(`backend/src/api.rs:1283`), отдаёт все TLS CA конкатенацией в одном PEM.
Эндпоинт публичный: у него нет auth-guard в сигнатуре, и глобального
auth-fairing в `backend/src/lib.rs` нет. Новых scope сервисному аккаунту не
требуется.

Отвергнутая альтернатива — брать цепочку из уже расшифрованного PKCS#12
(`pki.Bundle.Chain`): ставились бы только CA настроенных доменов и только в
момент реальной смены сертификата, поэтому ротация CA без выпуска новых сертов
осталась бы незамеченной.

Запрос идёт через существующий `vaultls.Client.do()`, чтобы бесплатно получить
retry с бэкоффом и однократный форс-реаутх на 401. Bearer-токен на публичном
эндпоинте безвреден.

## 3. Конфигурация

Новая **глобальная** секция (не per-domain: доверие — свойство хоста, а не
домена):

```yaml
ca_trust:
  enabled: false                                   # по умолчанию выключено
  # anchor_dir: /usr/local/share/ca-certificates   # override для нестандартных систем
  # update_command: "update-ca-certificates"
```

```go
type CATrust struct {
    Enabled       bool   `yaml:"enabled"`
    AnchorDir     string `yaml:"anchor_dir"`
    UpdateCommand string `yaml:"update_command"`
}
```

Поле `CATrust CATrust \`yaml:"ca_trust"\`` добавляется в `config.Config`.
Нулевое значение = выключено, поэтому существующие конфиги продолжают работать
без правок.

**Автодетект платформы** в `applyDefaults` — только когда `enabled: true` и
поля пусты:

| Условие                                             | anchor_dir                            | ext    | update_command            |
|-----------------------------------------------------|---------------------------------------|--------|---------------------------|
| существует `/usr/local/share/ca-certificates`        | он же                                 | `.crt` | `update-ca-certificates`  |
| существует `/etc/pki/ca-trust/source/anchors`        | он же                                 | `.pem` | `update-ca-trust extract` |
| иначе                                                | — ошибка конфига                      | —      | —                         |

Расширение файла выводится из `anchor_dir`: путь под `/etc/pki/` → `.pem`,
иначе `.crt`. Это делает override `anchor_dir` самодостаточным.

**Валидация** (`config.validate`) при `enabled: true`: `anchor_dir` — абсолютный
путь; `update_command` — непустая строка; если автодетект не сработал и поля не
заданы, ошибка называет оба поля явно.

## 4. Новый пакет `internal/catrust`

Единственная публичная точка входа:

```go
type Fetcher interface {
    CABundle(ctx context.Context) ([]byte, error)
}

type Runner interface {
    Run(ctx context.Context, command string) error
}

func Sync(ctx context.Context, f Fetcher, r Runner, cfg config.CATrust, stateDir string) (Result, error)

type Result struct {
    Installed int  // сколько сертификатов сейчас числится за агентом
    Changed   bool // менялось ли хранилище в этом прогоне
}
```

`Runner` инжектируется, чтобы тесты не запускали настоящий
`update-ca-certificates`; продовая реализация — обёртка над `reloader.Run`
(существующий `sh -c` с контекстом) с собственным таймаутом 60 s.

### 4.1 Алгоритм

1. `f.CABundle(ctx)` → PEM-поток.
2. Разбор потока в отдельные `*x509.Certificate`. Пустой результат или блок,
   не парсящийся как сертификат, — ошибка; анкор-каталог не трогается.
3. Для каждого сертификата вычисляется SHA-256 от DER и имя файла
   `vaultls-<slug(CN)>-<первые 8 hex fingerprint><ext>`. Slug: нижний регистр,
   всё кроме `[a-z0-9]` → `-`, схлопывание повторов, обрезка до 40 символов;
   пустой CN → `ca`. Fingerprint в имени гарантирует уникальность даже при
   одинаковых CN.
4. Чтение состояния `<stateDir>/ca-trust.json`: `fingerprint → filename`.
5. **Идемпотентность.** Если множество fingerprint'ов совпало с состоянием
   **и** все файлы физически существуют в `anchor_dir` — выход с
   `Changed: false`, `update_command` не запускается.
6. Иначе: новые файлы пишутся атомарно (`tmp` + `rename`, mode `0644` —
   публичные сертификаты, читать должны все).
7. Удаляются файлы, числящиеся в прошлом состоянии, но отсутствующие в новом
   bundle. Удаляются **только** пути из состояния — чужие анкоры в каталоге не
   трогаются никогда. Удаление обязательно: иначе выведенный из обращения CA
   остаётся доверенным вечно.
8. Состояние записывается атомарно (`0600`) **до** запуска `update_command`, с
   флагом `pending_update: true`: упавшая команда не должна приводить к потере
   учёта уже разложенных файлов.
9. `r.Run(ctx, cfg.UpdateCommand)` — один прогон на весь набор.
10. При успехе состояние перезаписывается с `pending_update: false` и свежим
    `last_sync`. Флаг обязателен: без него упавшая команда оставила бы агента в
    состоянии «всё сделано», и доверие не применилось бы никогда — шаг 5 счёл
    бы набор совпавшим и вышел бы без повторного запуска команды.
    Соответственно, `pending_update: true` в прочитанном состоянии сам по себе
    делает прогон необходимым.

### 4.2 Состояние

`<stateDir>/ca-trust.json`, где `stateDir` = `/etc/ssl/vaultls` (каталог уже
создаётся `postinstall.sh` с mode 0750 и уже входит в `ReadWritePaths`):

```json
{
  "certs": { "<sha256-hex>": "vaultls-vaultls-root-ca-1a2b3c4d.crt" },
  "pending_update": false,
  "last_sync": 1753848000000
}
```

Формат и подход к атомарной записи повторяют `internal/store` — но это
отдельный файл и отдельный тип, потому что `store.State` описывает один домен и
живёт в его `out_dir`.

## 5. Точка вызова

Новая функция `app.SyncCATrust(ctx, cfg, fetcher, m, log)`, вызываемая из `Run`
и `RunOnce` непосредственно перед `ReconcileAll`:

```go
func SyncCATrust(ctx context.Context, cfg *config.Config, f catrust.Fetcher, m *metrics.Metrics, log *slog.Logger)
```

Отдельная функция, а не расширение `ReconcileAll`: у последней уже есть тест на
изоляцию сбоев по доменам, и её сигнатура не должна тянуть за собой сущности
доверенного хранилища.

Это покрывает оба требования задачи разом:

- **обновление агента** — `apt upgrade` рестартует unit, старт вызывает
  initial `ReconcileAll`;
- **обновление сертификата** — каждый плановый прогон по `schedule` проверяет
  bundle заново, независимо от того, менялись ли сертификаты доменов.

Ошибка `Sync` логируется (`log.Error`) и инкрементит метрику, но **не**
прерывает reconcile доменов: недоступный CA-эндпоинт не должен блокировать
раскладку сертификатов. `RunOnce` вызывает тот же путь.

## 6. Метрики

| Метрика | Тип | Смысл |
|---|---|---|
| `vaultls_agent_ca_trust_certs` | gauge | сколько CA числится за агентом |
| `vaultls_agent_ca_trust_last_sync_timestamp_seconds` | gauge | момент последнего успешного `Sync` |
| `vaultls_agent_ca_trust_errors_total{stage}` | counter | `stage` = `fetch`\|`parse`\|`write`\|`update`\|`state` |

Метрики без лейблов домена — фича глобальна.

## 7. systemd

`ProtectSystem=full` делает read-only `/usr`, `/boot`, `/efi` и `/etc`, поэтому
без правки unit'а запись анкора и работа `update-ca-certificates` провалятся.
Итоговая строка в `packaging/systemd/vaultls-agent.service`:

```
ReadWritePaths=/etc/ssl/vaultls /etc/vaultls -/usr/local/share/ca-certificates -/etc/ssl/certs -/etc/pki/ca-trust/source/anchors -/etc/pki/ca-trust/extracted
```

Пути перечисляются всегда, независимо от `enabled`. Префикс `-` у новых путей
обязателен: без него отсутствующий каталог (не-Debian система, минимальный
образ) делает запуск unit'а фатальной ошибкой.

Сервис работает от root, `NoNewPrivileges=yes` запуску `update-ca-certificates`
не мешает.

## 8. Жизненный цикл

- **`enabled: false`** — агент не трогает ничего, даже если ранее что-то
  установил. Выключение флага не должно внезапно ломать TLS у зависимых
  сервисов; снятие доверия — явное действие оператора.
- **`apt purge`** — `postremove.sh` при `purge` читает
  `/etc/ssl/vaultls/ca-trust.json`, удаляет перечисленные файлы из анкор-каталога,
  прогоняет `update-ca-certificates` (или `update-ca-trust extract`, если первой
  команды нет) и удаляет сам файл состояния. Всё best-effort, `|| true`.
- **`apt remove`** (без purge) — не трогает, конфиг и доверие остаются.

## 9. setup / документация

- `vaultls-agent setup` получает флаг `--ca-trust` (bool, default `false`);
  `wizard.Answers` — поле `CATrust bool`, `wizard.Render` пишет секцию
  `ca_trust: {enabled: ...}` только когда флаг взведён. Интерактивный опрос
  новым вопросом **не** дополняется — фича опциональная и админская.
- `packaging/config.example.yaml` — закомментированный блок `ca_trust` с
  пояснением, что включение меняет доверие всего хоста.
- `api-client/README.md` — раздел «System trust store» с примером и указанием
  на override `anchor_dir`/`update_command` для не-Debian систем.

## 10. Тесты

`internal/catrust/catrust_test.go` — на `t.TempDir()` в роли анкор-каталога и
fake-`Runner`, считающем вызовы:

1. Первый прогон: два CA в bundle → два файла на диске, `Runner` вызван один
   раз, состояние содержит два fingerprint'а.
2. Повторный прогон с тем же bundle → `Changed: false`, `Runner` **не** вызван,
   mtime файлов не изменился.
3. Bundle сменился (один CA ушёл, один добавился) → старый файл удалён, новый
   создан, `Runner` вызван один раз.
4. Файл руками удалён из анкор-каталога при неизменном состоянии → прогон
   восстанавливает файл и зовёт `Runner` (проверка шага 5 алгоритма).
5. Чужой файл `other.crt` в каталоге переживает все прогоны.
6. Битый PEM → ошибка, каталог и состояние не изменились.
7. `Runner` вернул ошибку → `Sync` возвращает ошибку, состояние записано с
   `pending_update: true`; следующий прогон с тем же bundle снова вызывает
   `Runner` и по успеху снимает флаг.

`internal/config/load_test.go` — автодетект anchor_dir, ошибка при
`enabled: true` без детекта и без override, обратная совместимость конфига без
секции.

`internal/vaultls/client_test.go` — `CABundle` на httptest-сервере: успех, 404,
5xx с retry.

`internal/metrics/metrics_test.go` — три новые серии присутствуют в выдаче.

## 11. Затрагиваемые файлы

| Файл | Изменение |
|---|---|
| `internal/catrust/catrust.go` | новый |
| `internal/catrust/state.go` | новый |
| `internal/catrust/catrust_test.go` | новый |
| `internal/config/config.go` | тип `CATrust`, поле в `Config` |
| `internal/config/load.go` | автодетект + валидация |
| `internal/vaultls/client.go` | метод `CABundle` |
| `internal/metrics/metrics.go` | три метрики + сеттеры |
| `internal/app/app.go` | `SyncCATrust` + вызов из `Run`/`RunOnce` |
| `internal/wizard/wizard.go` | поле `CATrust`, рендер секции |
| `cmd/vaultls-agent/setup.go` | флаг `--ca-trust` |
| `packaging/systemd/vaultls-agent.service` | `ReadWritePaths` |
| `packaging/scripts/postremove.sh` | чистка при purge |
| `packaging/config.example.yaml` | блок `ca_trust` |
| `api-client/README.md` | раздел документации |
