# vaultls-agent — deb-пакет с Go-клиентом (дизайн)

- Дата: 2026-06-26
- Профиль: architect + devops
- Статус: утверждён к планированию
- Расположение в репозитории: `api-client/`

## 1. Назначение и границы

`vaultls-agent` — долгоживущий systemd-сервис под Debian amd64, аналог
certbot, но источник сертификатов — **VaulTLS API** (не ACME). Сервис:

- по расписанию (cron-spec, по умолчанию раз в месяц) забирает TLS-серты из
  VaulTLS по сервисному аккаунту (`client_id` + `secret`);
- раскладывает их в PEM на хост (`/etc/ssl/vaultls/<domain>/`);
- при **реальном** изменении сертификата (смена serial) перезагружает
  указанную службу;
- отдаёт Prometheus-метрики о состоянии, расписании и проблемах обновления.

Вне границ (YAGNI на этот этап): выпуск/отзыв сертов, ACME, SSH-серты,
apt-репозиторий с GPG (только `.deb`-артефакт в GitHub Releases),
push в Pushgateway (только pull `/metrics`).

## 2. Контракт VaulTLS API (как клиент его использует)

Установлено по исходникам backend (Rust):

- Авторизация сервисного аккаунта: `POST /api/auth/token` с телом
  `{client_id, secret}` → `{access_token (JWT), token_type, expires_in, scopes}`.
  Нужен scope `cert:read`.
- Список: `GET /certificates` (Bearer) → массив объектов с полями
  `id, name, created_on, valid_until, certificate_type, user_id, ca_id,
  revoked_at`. **Поле `data` (а значит и serial) в JSON отсутствует**
  (`#[serde(skip)]`).
- Пароль серта: `GET /certificates/<id>/password` → строка.
- Скачивание: `GET /certificates/<id>/download` → для TLS это **PKCS12 (.p12)**,
  защищённый паролем (leaf + private key + chain).

Поведение renew в VaulTLS: создаётся **новая запись** (новый `id`, новый
`valid_until`) с тем же `name`; старая запись может оставаться/отзываться.
Поэтому клиент для имени серта выбирает запись с максимальным `valid_until`
среди не отозванных (`revoked_at == null`).

### Стратегия детектирования обновления

1. Дешёвая проверка без скачивания: сравнить `(cert_id, valid_until)` из
   листинга с локальным состоянием.
2. Финальная сверка перед reload: serial извлекается из скачанного `.p12` и
   сравнивается с сохранённым serial. Reload выполняется только при реальной
   смене serial. Это совпадает с требованием «храним серийник рядом с сертами».

## 3. Архитектура (Go-пакеты)

```
api-client/
├── cmd/vaultls-agent/          # main: подкоманды run | setup | check | version
├── internal/
│   ├── config/                 # загрузка/валидация /etc/vaultls/config.yaml, дефолты
│   ├── vaultls/                # API-клиент: token, list, download p12, password
│   ├── pki/                    # p12 → PEM (fullchain/privkey/cert/chain + haproxy.pem), serial
│   ├── store/                  # состояние рядом с сертами: serial + cert_id + valid_until
│   ├── reconcile/              # ядро: сравнить → скачать → разложить → reload (per-domain)
│   ├── scheduler/              # внутренний планировщик (cron-spec + jitter)
│   ├── reloader/               # exec reload-команды, проверка результата
│   ├── metrics/                # prometheus-exporter (/metrics)
│   ├── selfupdate/             # проверка версии в GitHub Releases
│   └── wizard/                 # интерактивный setup + неинтерактивный из флагов
├── packaging/nfpm.yaml         # описание deb
├── packaging/systemd/vaultls-agent.service
└── packaging/config.example.yaml
```

Принципы: один пакет — одна ответственность. `pki`, `store`, `reconcile` —
чистая логика с инъекцией зависимостей (API-клиент, файловая система через
интерфейсы), тестируется изолированно без сети.

## 4. Конфиг `/etc/vaultls/config.yaml`

```yaml
server:
  url: https://vaultls.example.com
  client_id: svc_xxxxxxxx
  secret: ${VAULTLS_SECRET}      # или строкой; файл root:root 0600
  insecure_skip_verify: false    # для self-signed; по умолчанию строгий TLS
schedule: "0 3 1 * *"            # cron-spec: 03:00 1-го числа (раз в месяц)
jitter: 30m                      # размазать нагрузку
exporter:
  listen: "127.0.0.1:9105"
domains:
  - name: "*.example.com"        # имя серта в VaulTLS (wildcard указывается явно)
    out_dir: /etc/ssl/vaultls/example.com   # дефолт: /etc/ssl/vaultls/<name без *.>
    formats: [pem, haproxy]      # pem=4 файла; haproxy=fullchain+privkey в одном
    owner: root
    group: ssl-cert
    mode: "0640"                 # privkey всегда 0600 независимо от mode
    reload: "systemctl reload nginx"
    cert_id: 123                 # опционально: жёстко зафиксировать, минуя поиск по имени
```

### Маппинг домен → серт (с учётом wildcard)

- В большинстве случаев на хост идут wildcard-серты, поэтому в `name`
  указывается прямое имя серта в VaulTLS, например `*.example.com`.
- Поиск: среди не отозванных записей `GET /certificates` берём с
  `name == domains[].name`; при нескольких совпадениях — с максимальным
  `valid_until`.
- Явный `cert_id` переопределяет поиск по имени.

### Раскладка файлов (`out_dir`)

Формат `pem` (как certbot):

- `fullchain.pem` (leaf + chain)
- `privkey.pem` (0600)
- `cert.pem` (только leaf)
- `chain.pem` (только промежуточные/CA)

Формат `haproxy`: `haproxy.pem` = leaf + chain + privkey в одном файле (0600).

Рядом — состояние `.vaultls-state.json` (см. §6).

## 5. Поток reconcile (на каждый домен, изолированно)

1. Получить JWT: `POST /api/auth/token` (кэш в памяти до `expires_in`,
   один авто-reauth при 401).
2. `GET /api/certificates` → найти запись по `name`/`cert_id`. Дешёвая проверка:
   `(cert_id, valid_until)` против `store`.
3. Если идентичность не изменилась (`(cert_id, valid_until)` совпали и serial
   уже сохранён) → **skip** (обновить метрики, на диск ничего не писать).
   В pull-архитектуре renew на сервере = новая запись с новым `id`/`valid_until`,
   поэтому проверка идентичности сама ловит обновление; отдельный `renew_before`
   не нужен и удалён.
4. Иначе: `GET /certificates/<id>/password` + `GET /certificates/<id>/download`
   (p12).
5. `pki`: распаковать p12, извлечь serial. **Если serial == сохранённого →
   skip reload** (защита от ложного срабатывания).
6. Атомарно записать выбранные форматы (temp-файл + `rename`, privkey 0600,
   выставить owner/group/mode), обновить `store` (serial, cert_id, valid_until).
7. Выполнить `reload` **только** если на шаге 5 serial реально новый.
   Результат reload → в метрики.

Идемпотентность: запись атомарна (rename), reload только при смене serial,
повторный прогон без изменений на сервере — no-op.

## 6. Состояние (`store`)

Файл `.vaultls-state.json` в `out_dir` каждого домена:

```json
{ "cert_id": 123, "serial": "0A1B2C...", "valid_until": 1790000000000,
  "last_check": 1782000000000, "last_renewal": 1782000000000 }
```

Используется для дешёвой проверки и для экспонирования метрик без обращения
к серверу при scrape.

## 7. Метрики (`/metrics`)

- `vaultls_agent_up`
- `vaultls_agent_build_info{version}`
- `vaultls_agent_update_available` (0/1)
- `vaultls_agent_latest_version_info{version}` — последняя версия из GitHub
- Per-domain:
  - `vaultls_cert_expiry_timestamp_seconds{domain}`
  - `vaultls_cert_serial_info{domain,serial}`
  - `vaultls_last_check_timestamp_seconds{domain}`
  - `vaultls_last_renewal_timestamp_seconds{domain}`
- `vaultls_reconcile_errors_total{domain,stage}`
- `vaultls_reload_failures_total{domain}`
- `vaultls_scrape_token_errors_total`

Покрывает «состояние», «список джоб» (per-domain серии) и «проблемы с
обновлением» (errors/reload_failures/update_available).

## 8. Обработка ошибок (fail-safe)

- Ошибка по одному домену **не валит** остальные (изоляция per-domain),
  пишется в `*_errors_total{stage}` и в journald.
- Сетевые/5xx → экспоненциальный backoff внутри одного прогона, ограниченное
  число попыток.
- Битый p12 / неверный пароль / пустой список / домен не найден → ошибка
  домена, **старые серты на диске не трогаем** (продолжаем работать на старом
  серте).
- Token expired → один автоматический re-auth, при повторной неудаче — ошибка
  и метрика `vaultls_scrape_token_errors_total`.

## 9. deb-пакет (nfpm)

Раскладка:

- бинарь → `/usr/bin/vaultls-agent`
- unit → `/lib/systemd/system/vaultls-agent.service`
- пример конфига → `/etc/vaultls/config.example.yaml` (как `conffile`,
  обновление пакета не перетирает пользовательский `config.yaml`)

systemd unit (hardening):

- запуск от root (нужен доступ к `/etc/ssl`), но
  `NoNewPrivileges=yes`, `ProtectSystem=full`, `ProtectHome=yes`,
  `ReadWritePaths=/etc/ssl/vaultls /etc/vaultls`
- `Restart=on-failure`, `Type=simple`, `ExecStart=/usr/bin/vaultls-agent run`

`postinst`:

- `systemctl daemon-reload`
- если `config.yaml` отсутствует — **не** стартуем автоматически, печатаем
  подсказку: запустить `vaultls-agent setup`

Установка/первичная настройка `vaultls-agent setup`:

- если переданы все обязательные флаги (`--url --client-id --secret
  --domain ... --reload ...`) → пишем `config.yaml` non-interactive (пригодно
  для ansible/CI);
- если чего-то не хватает → интерактивный wizard допрашивает недостающие
  поля повопросно;
- по завершении — `systemctl enable --now vaultls-agent`.

## 10. Версия и самопроверка обновления

При старте и далее раз в сутки `selfupdate` дёргает GitHub Releases API
(`/repos/<owner>/<repo>/releases/latest`). При отставании текущей версии:

- WARN в journald;
- `vaultls_agent_update_available=1` и `vaultls_agent_latest_version_info`.

Сетевые ошибки проверки версии не влияют на основную работу (best-effort).

## 11. Распространение

- CI собирает `.deb` (nfpm) и публикует в GitHub Releases.
- Установка: `wget` + `dpkg -i` (или `apt install ./vaultls-agent_*.deb`).
- apt-репозиторий с GPG-подписью — отдельный возможный шаг в будущем
  (вне текущего scope).

## 12. Тестирование

- Unit:
  - `pki` — фикстуры `.p12` → PEM, извлечение serial, формат haproxy;
  - `config` — валидация и дефолты, раскрытие `${ENV}`;
  - `reconcile` — мок API-клиента: сценарии «serial сменился» / «не сменился» /
    «домен не найден» / «p12 битый»;
  - `scheduler` — парсинг cron-spec и применение jitter.
- Integration:
  - `httptest`-сервер, эмулирующий VaulTLS (token/list/download/password),
    полный прогон reconcile во временный каталог, проверка атомарности и прав.
- Без выхода в реальную сеть; `selfupdate` за интерфейсом, мокается.

## Решённые при реализации детали

- Путь авторизации: `POST /api/auth/token`; листинг `GET /api/certificates`;
  скачивание `GET /api/certificates/<id>/download`; пароль
  `GET /api/certificates/<id>/password` (подтверждено по роутингу backend).
- `renew_before` удалён: в pull-архитектуре обновление детектируется по
  `(cert_id, valid_until)` из листинга, отдельный порог не нужен.
- `owner/group/mode` применяются к PEM-файлам; privkey принудительно 0600
  вне зависимости от `mode`.
