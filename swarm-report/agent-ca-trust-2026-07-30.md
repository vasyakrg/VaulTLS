# Отчёт: установка корневых CA VaulTLS в системное доверенное хранилище

- Дата: 2026-07-30
- Профиль: business-feature
- Статус: **Done**
- Ветка: `feat/agent-ca-trust` → смержена в `main` (`37de63c`), не запушена
- Пакет: `api-client/dist/vaultls-agent_0.3.0_amd64.deb`, локальный тег `agent-v0.3.0`

## Задача

Научить `vaultls-agent` устанавливать корневые сертификаты VaulTLS в систему
(`/etc/ssl`), чтобы любой локальный сервис доверял импортируемому сертификату.
Управление отдельной переменной, по умолчанию выключено. При обновлении агента
или сертификата корневик проверяется и при необходимости обновляется.

## Research

Консилиум субагентов не запускался — сессия запрещает вызывать агентов без
явного запроса пользователя. Разведка выполнена в основном контексте:

- Агент — Go, `api-client/`, systemd-сервис; `reconcile.Domain` тянет PKCS#12,
  раскладывает PEM в `out_dir`, дёргает reload.
- Бэкенд отдаёт `GET /api/certificates/ca/bundle` (`backend/src/api.rs:1283`) —
  все TLS CA одним PEM. Эндпоинт публичный: auth-guard в сигнатуре нет,
  глобального auth-fairing в `lib.rs` нет. Новых scope сервисному аккаунту не
  требуется.
- Unit имеет `ProtectSystem=full` — `/usr` и `/etc` read-only, значит запись
  анкоров и `update-ca-certificates` требуют новых `ReadWritePaths`.

## Решения

| Развилка | Решение |
|---|---|
| Источник CA | `GET /api/certificates/ca/bundle` — ловит ротацию CA даже когда сертификаты доменов не менялись |
| Гранулярность | Глобальная секция `ca_trust`, не per-domain: доверие — свойство хоста |
| При `enabled: false` | Ничего не трогаем; снятие доверия — явное действие оператора или `apt purge` |
| Раскладка | Один сертификат на файл: `update-ca-certificates` хеширует только первый блок multi-PEM |
| Платформа | Автодетект Debian/RHEL по существованию каталога + override в конфиге |

Документы: спека `docs/superpowers/specs/2026-07-30-agent-ca-trust-design.md`,
план `docs/superpowers/plans/2026-07-30-agent-ca-trust.md`.

## Реализация

Subagent-driven development: 9 задач, отдельный субагент-имплементер (sonnet) и
отдельный ревьюер на каждую. 22 файла, +1725/−12.

| Задача | Результат |
|---|---|
| 1 | `vaultls.Client.CABundle` через существующий `do()` (retry + re-auth) |
| 2 | `config.CATrust{Enabled, AnchorDir, UpdateCommand}`, `FileExt()`, автодетект, валидация |
| 3 | `catrust.ParseBundle` → `Anchor{Fingerprint, FileName, PEM}` |
| 4 | `catrust.State`/`ReadState`/`WriteState` — учёт своих файлов + `pending_update` |
| 5 | `catrust.Sync` — идемпотентность, удаление отозванных, подметание temp, `ShellRunner` |
| 6 | Метрики `vaultls_agent_ca_trust_{certs,last_sync_timestamp_seconds,errors_total{stage}}` |
| 7 | `app.SyncCATrust` в `Run` (старт + плановый цикл) и `RunOnce` |
| 8 | Флаг `setup --ca-trust`, рендер секции только при запросе |
| 9 | `ReadWritePaths`, чистка при `apt purge`, `config.example.yaml`, README |

## Validation

- `go vet ./...` — чисто
- `go test ./...` — 14 пакетов, все проходят (100 тестов)
- `make build` + `make deb VERSION=0.3.0` — пакет собран, содержит бинарь, unit и `config.example.yaml`
- Проверка на живом Debian-хосте **не проводилась** — деплой-скрипта у проекта нет,
  пакет собран локально. Ручной сценарий описан в конце плана.

## Найденное ревью

Финальное whole-branch ревью (Opus) поймало то, что не увидели потасочные ревью:

1. **Critical.** `io.ReadAll` в `client.go` глотал ошибку чтения тела — оборванный
   на полпути ответ приходил как 200 с частичным PEM. `ParseBundle` молча
   отбрасывал недописанный блок, `Sync` считал недополученный CA отозванным,
   удалял его анкор и применял хранилище. При дефолтном `schedule: "0 3 1 * *"`
   доверие вернулось бы только через месяц. Исправлено: ошибка чтения
   пропагируется как transient, `ParseBundle` отвергает хвостовые байты.
2. **Important.** Сбой записи посреди цикла оставлял анкор на диске без записи в
   state — файл доверенный навсегда, невидимый и для ретайра, и для purge.
3. **Important.** Хардкод `/etc/ssl/vaultls` в `app.go` — любой будущий тест
   писал бы в реальный системный путь.

Первая fix-волна пункты 2 и 3 из этого списка починила, но пункты «сохранить
учёт при частичном сбое» и «спрятать temp-файл от trust-тулинга» сделала хуже:
`WriteState` затирал прежний учёт, а `.vaultls-tmp-<имя>.crt` подхватывался
Debian'овским `find -name '*.crt'`. Вторая волна (Opus) закрыла обе:
`union(prev, next)` и temp-имя без расширения + `sweepStaleTempAnchors`.

## Осознанно отложено

- `writeAnchor` не удаляет свой temp на обработанной ошибке rename — остаток
  подметается следующим пишущим прогоном, не сразу
- подметание стоит после `needsSync`
- `postremove.sh` не чистит `.vaultls-tmp-*`
- неудаляемый temp-файл жёстко блокирует синк (fail-closed by design)
- смена `anchor_dir` между Debian/RHEL оставляет файл со старым именем

## Что дальше

- Проверить на тестовом Debian-хосте (`dpkg -i`, `ca_trust.enabled: true`, `curl` без `--cacert`)
- `git push` + `git push origin agent-v0.3.0` — тег запускает workflow `agent-release`
