# vaultls (Helm chart)

Helm-чарт для [VaulTLS](https://github.com/7ritn/vaultls) — self-hosted менеджера mTLS-сертификатов (Rust + SQLite). Включает консистентный бекап данных в S3 через **restic** (CronJob).

## Что разворачивается

| Ресурс | Назначение |
|--------|-----------|
| Deployment | приложение `ghcr.io/vasyakrg/vaultls`, 1 реплика, `strategy: Recreate` |
| PVC | данные `/app/data` (SQLite, CA, ключи, CRL), RWO |
| Service | ClusterIP :80 |
| Ingress | внешний доступ, TLS через готовый secret `tls-example-ingress` |
| Secret | `VAULTLS_API_SECRET`, `VAULTLS_DB_SECRET`, OIDC, S3-креды, restic-пароль |
| CronJob | ежедневный бекап в S3 |
| ConfigMap | скрипт бекапа `backup.sh` |

> **Почему 1 реплика и `Recreate`:** SQLite + том RWO не допускают двух одновременных писателей. Масштабирование приложения не поддерживается архитектурой VaulTLS.

## Установка

```bash
cp values.yaml values-prod.yaml
# заполнить секреты в values-prod.yaml (gitignored — НЕ коммитить)

helm upgrade --install vaultls . \
  -n vaultls --create-namespace \
  -f values-prod.yaml
```

Генерация секретов:
```bash
openssl rand -base64 32   # apiSecret, dbSecret
openssl rand -base64 24   # restic password
```

## Бекап

CronJob по расписанию (`backup.schedule`, по умолчанию `0 3 * * *`):

1. Монтирует тот же PVC, что и приложение (через `podAffinity` встаёт на ту же ноду — иначе RWO-том не примонтируется).
2. Делает **консистентный** снимок каждой SQLite-базы: `sqlite3 <db> ".backup ..."` (безопасно при активной записи — без риска битого файла).
3. Архивирует остальные файлы (CA, приватные ключи, CRL).
4. `restic backup` в S3 — инкрементально, с шифрованием на стороне клиента (приватные ключи не попадают в S3 в открытом виде).
5. `restic forget --prune` по retention-политике (`keepDaily`/`keepWeekly`/`keepMonthly`).

Запустить бекап немедленно:
```bash
kubectl -n vaultls create job --from=cronjob/vaultls-backup vaultls-backup-manual
kubectl -n vaultls logs -f job/vaultls-backup-manual
```

> **Важно:** `restic.password` — единственный ключ к расшифровке бекапа. Храните его отдельно от кластера. Без него восстановление невозможно.

## Восстановление

Запустить временный под с доступом к S3 и restic:

```bash
kubectl -n vaultls run restic-restore --rm -it --restart=Never \
  --image=alpine:3.21 -- sh

# внутри пода:
apk add --no-cache restic
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
export RESTIC_PASSWORD=<restic password>
export RESTIC_REPOSITORY="s3:https://s3.example.com/backups/vaultls"

restic snapshots                       # список снапшотов
restic restore latest --target /restore
ls -R /restore                         # содержимое /app/data
```

Затем содержимое `/restore` скопировать в PVC приложения (например, `kubectl cp` во временный под, примонтировавший PVC, при остановленном Deployment), и поднять приложение.

Восстановление прямо в PVC (Deployment предварительно остановить — `kubectl scale deploy/vaultls --replicas=0`):

```bash
# под, монтирующий PVC vaultls в /app/data, с теми же env restic:
restic restore latest --target / --include /app/data
# или восстановить в /stage и rsync в /app/data
```

## Основные параметры values

| Ключ | По умолчанию | Описание |
|------|--------------|----------|
| `image.tag` | `latest` | версия образа vaultls |
| `config.url` | `https://vaultls.example.com/` | `VAULTLS_URL` |
| `config.logLevel` | `info` | `VAULTLS_LOG_LEVEL` |
| `secrets.apiSecret` | — (обязателен) | `VAULTLS_API_SECRET` |
| `secrets.dbSecret` | `""` | шифрование БД на диске; пусто = без шифрования |
| `secrets.existingSecret` | `""` | использовать готовый Secret вместо генерации |
| `persistence.size` | `1Gi` | размер PVC |
| `persistence.storageClass` | `""` | пусто = default класс |
| `ingress.host` | `vaultls.example.com` | хост |
| `ingress.tls.secretName` | `tls-example-ingress` | готовый TLS-secret |
| `backup.enabled` | `false` | включить CronJob бекапа |
| `backup.schedule` | `0 3 * * *` | расписание |
| `backup.restic.s3Endpoint` | `""` | endpoint S3 (со схемой для MinIO http) |
| `backup.restic.password` | — (обязателен при backup) | ключ шифрования restic |
| `backup.restic.keepDaily/Weekly/Monthly` | `7/4/6` | retention |

Полный список — в `values.yaml`.

## OIDC (опционально)

Задать `config.oidc.authUrl`, `config.oidc.callbackUrl` и `secrets.oidcClientId` / `secrets.oidcClientSecret`. Пустой `authUrl` отключает OIDC.
