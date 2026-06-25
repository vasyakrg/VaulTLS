# Spec: импорт внешних CA и сертификатов

Статус: draft · Фаза 1 roadmap форка · Связано с upstream issue
[#193](https://github.com/7ritn/vaultls/issues/193).

## Цель

Добавить возможность импортировать в VaulTLS:
- **(A) Свой CA с приватным ключом** (например, созданный openssl). VaulTLS получает полный
  контроль: выпуск новых сертов, CRL, ACME.
- **(B) Купленный листовой сертификат от публичного CA** (DigiCert/Sectigo/Let's Encrypt) —
  cert+key, которые уже есть у пользователя. Приватного ключа CA **нет**; его цепочка
  импортируется как **read-only external CA** (только хранение/выдача, без выпуска/CRL).

При импорте сертификата его CA **автоимпортируется автоматически** из цепочки (решение по
дизайну: единые эндпоинты, авто-импорт CA, упрощённая иерархия).

## Что уже есть в коде (опора)

- `ca_certificates.key` BLOB **уже nullable** — запись CA без ключа структурно возможна.
- `CertData` enum уже имеет `Pkcs12(Vec<u8>) | Pem(Vec<u8>) | SshBundle(Vec<u8>)`
  (`backend/src/certs/common.rs`).
- Парсинг уже реализован: `X509::from_pem/from_der`, `Pkcs12::from_der().parse2(password)`
  (даёт `.cert`, `.pkey`, `.ca`-цепочку), извлечение serial/SAN/issuer/subject
  (`backend/src/certs/tls_cert.rs`).
- Admin-guard `AuthenticatedPrivileged` (`backend/src/auth/session_auth.rs:89-103`) —
  переиспользуем на новых роутах.
- PKCS#12-упаковка с цепочкой через `Pkcs12::builder().ca(stack).cert().pkey()`
  (`tls_cert.rs:build_common`).

## Модель данных

### Миграция `backend/migrations/11-import/`
```sql
-- up.sql
ALTER TABLE ca_certificates ADD COLUMN is_imported INTEGER NOT NULL DEFAULT 0;
```
- `is_imported` — только UX-метка («внутренний» vs «импортированный»). Для доменной логики
  «можно ли выпускать» используем **наличие ключа**, а не эту колонку.
- Отдельная колонка `has_private_key` **не нужна**: вычисляется как `!key.is_empty()`.
- Иерархия (`parent_ca_id`) **не добавляется** (решение «упрощённо»): запись CA = непосредственный
  issuer импортируемого серта; полная цепочка до корня сохраняется внутри p12/серта.

### Правки структур и чтения
- `backend/src/certs/common.rs` — структура `CA`:
  - добавить `pub is_imported: bool`;
  - добавить метод `impl CA { pub fn has_private_key(&self) -> bool { !self.key.is_empty() } }`.
- `backend/src/db.rs` — **критичный фикс чтения NULL-ключа**: в `get_ca_by_query` и `get_all_ca`
  заменить `key: row.get(6)?` → `key: row.get(6).unwrap_or_default()` (иначе CA без ключа
  валит SELECT). Во все SELECT/INSERT по `ca_certificates` добавить `is_imported`.
  Обновить `insert_ca` (принимает `ca.is_imported`).

## API

Rocket: добавить feature `forms` в `backend/Cargo.toml`
(`rocket = { version="0.5.1", features=["json","secrets","forms"] }`) для приёма файлов
(`rocket::form::Form`, `rocket::fs::TempFile`). Оба роута — guard `AuthenticatedPrivileged`.
Монтирование в `backend/src/lib.rs` (`openapi_get_routes![...]`).

### `POST /api/certificates/ca/import` (multipart/form-data)
Импорт CA напрямую (сценарий A или предварительный импорт external-CA).

| Поле | Тип | Обяз. | Описание |
|------|-----|-------|----------|
| `ca_cert` | file (PEM/DER) | да | сертификат CA |
| `ca_key` | file (PEM/DER, PKCS8) | нет | приватный ключ; без него CA = read-only |
| `crl` | file | нет | начальный CRL (опц.) |
| `name` | text | нет | имя; по умолчанию CN из subject |
| `ca_type` | text | нет | `tls`/`ssh`; по умолчанию авто (TLS, если X.509) |

Возврат: `Json<i64>` (id созданного CA).

### `POST /api/certificates/import` (multipart/form-data)
Импорт готового листового сертификата (сценарий B). Принимает **либо** p12, **либо** cert+key.

| Поле | Тип | Обяз. | Описание |
|------|-----|-------|----------|
| `p12` | file | * | PKCS#12 (cert+key+chain) |
| `password` | text | при p12 | пароль p12 |
| `cert` | file (PEM/DER) | * | листовой сертификат (альтернатива p12) |
| `key` | file (PEM/DER) | при cert | приватный ключ листового серта |
| `chain` | file (PEM bundle) | нет | цепочка CA, если её нет в p12/cert |
| `user_id` | text | да | владелец |
| `ca_id` | text | нет | если задан — привязать к этому CA; если нет — **авто из цепочки** |
| `renew_method` | text | нет | `None` по умолчанию (внешний серт обычно не продлеваем) |
| `cert_type` | text | нет | авто из EKU: `TLSServer`/`TLSClient` |

Поведение `ca_id` не задан → распарсить цепочку, найти/создать external-CA (см. ниже), привязать.
Возврат: `Json<Certificate>`.

## Крипто: новый модуль `backend/src/certs/import.rs`

```
parse_uploaded_cert(bytes)  -> X509          // try PEM, then DER
parse_uploaded_key(bytes)   -> PKey<Private> // try PEM/DER, PKCS8
parse_pkcs12(bytes, pass)   -> (X509 leaf, Option<PKey>, Vec<X509> chain)
parse_pem_bundle(bytes)     -> Vec<X509>     // split PEM-блоков
classify(cert)              -> Root|Intermediate|Leaf  // BasicConstraints CA + self-signed
find_issuing_ca(chain,leaf) -> X509          // cert чей subject == leaf.issuer
verify_chain(leaf, chain)   -> Result<()>    // X509Store + X509StoreContext::verify_cert
```

- **Верификация цепочки** — через `X509StoreBuilder` (добавить root+intermediates) +
  `X509StoreContext::verify_cert` (openssl-rs; полная проверка подписи, дат, BasicConstraints).
  Это надёжнее ручной проверки подписи и закрывает безопасность импорта. Импорт **отклоняется**,
  если цепочка не верифицируется (для (B) допускаем «цепочка без приватных ключей CA», но
  подпись leaf→issuer обязана сходиться).
- **Автоимпорт CA** (`ca_id` не задан): взять `find_issuing_ca`, дедуп по subject DN + SKI среди
  существующих CA (`get_all_ca`); если найден — вернуть его id; иначе `insert_ca` с `key=[]`,
  `is_imported=true`, `cert` = issuer DER. Корень/промежуточные выше issuer'а в отдельные записи
  не пишем (упрощённо) — они остаются в p12/серте для скачивания цепочки.

## Гард-точки: блокировать операции на CA без ключа

Во всех точках, использующих приватный ключ CA, добавить проверку `if !ca.has_private_key()
{ return Err(ApiError::BadRequest("CA has no private key; operation not allowed")) }`:

| # | Операция | Файл:строка (ориентир) |
|---|----------|------------------------|
| 1 | Выпуск TLS-серта | `certs/tls_cert.rs:set_ca` (~150) / `api.rs:create_user_certificate` (~382) |
| 2 | Выпуск SSH-серта | `certs/ssh_cert.rs:set_ca` (~81) / `api.rs` (~474) |
| 3 | ACME finalize (выпуск из CSR) | `acme/routes.rs:finalize_order` (~609) |
| 4 | CRL при revoke (TLS) | `api.rs:revoke_certificate` (~714) → `tls_cert.rs:create_crl` |
| 5 | KRL при revoke (SSH) | `api.rs` (~719) → `ssh_cert.rs:create_krl` |
| 6 | CRL on-the-fly | `api.rs:download_crl` (~743) |
| 7 | KRL on-the-fly | `api.rs:download_crl` (~769) |

Предпочтительно централизовать проверку в `set_ca`/получении issuing-CA, плюс явная проверка
в ACME-finalize и revoke/CRL-путях (они не идут через builder).

## Frontend (только контракт; реализация — Phase 3)

Новые экраны импорта проектируются в Phase 3 (полный редизайн). Здесь фиксируем контракт API,
чтобы фронт мог на него опереться: формы загрузки (drag-drop p12/PEM), выбор/автоопределение CA,
превью распарсенной цепочки (CN, срок, issuer) перед подтверждением.

## Тестирование

- **Unit (`cargo test --features test-mode`):** парсинг PEM/DER/p12 с паролем; `verify_chain`
  принимает корректную цепочку и **отклоняет** серт, подписанный другим CA; `classify`
  (root/intermediate/leaf); автоимпорт-дедуп (повторный импорт того же CA не плодит записи);
  гард — выпуск/CRL на keyless-CA возвращает BadRequest.
- **Integration:** Rocket test client — оба import-роута (200 на валидных данных, 4xx на битых).
- **E2E (`curl`):**
  - (A) openssl-CA `ca.crt`+`ca.key` → `/certificates/ca/import` → выпуск нового серта работает.
  - (B) листовой серт от публичного CA + `fullchain` без ключа CA → `/certificates/import`
    (авто-CA) → серт виден в списке и скачивается; выпуск через этот CA отклоняется.
  - reject: серт + чужой CA → 4xx.

## Риски и открытые вопросы

- **openssl без встроенного chain-verifier** — используем `X509Store`/`X509StoreContext`
  (поддерживается в openssl-rs). Проверить поведение при неполной цепочке (leaf+root без
  intermediate) — такой импорт должен давать понятную ошибку.
- **p12 vs cert+key** — поддерживаем оба входа (vloschiavo в #193 имеет cert+key, мейнтейнер
  предпочитает p12). Внутри храним как раньше — p12 в `user_certificates.data`.
- **SSH-импорт** — в этой фазе вторичен; модель и эндпоинт общие, но парсинг SSH-CA проще
  (ssh_key `PrivateKey::from_bytes`, без цепочки). Допустимо реализовать TLS-путь первым,
  SSH — следом.
- **Дедуп CA** по subject DN + SKI: возможны коллизии cross-signed — для упрощённой модели
  принимаем первый матч.
```
