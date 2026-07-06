# Управление группами сертификатов — дизайн

Дата: 2026-07-06
Статус: утверждается

## Цель

Ввести **группы** как слой контроля доступа к user-сертификатам. Сертификаты
объединяются в группы, группами «обвязываются» пользователи. Пользователь видит
сертификат, если он его владелец **или** состоит в общей с сертификатом группе.
Управление группами доступно только **локальному** (не-OIDC) администратору.

Сертификат может входить в несколько групп, пользователь — в несколько групп;
видимость определяется непустым пересечением.

## Классификация актора

Права зависят не только от роли, но и от способа входа. В `Claims` (JWT) сейчас
только `{id, role, service}` — признака локальности нет. Добавляем поле:

```rust
pub(crate) struct Claims {
    // ...существующие...
    #[serde(default)] // старые токены → false (безопасный дефолт)
    pub(crate) is_local: bool,
}
```

`is_local` проставляется в точке выпуска токена:
- `generate_token(..., is_local)` — из `login` (локальный пароль) → `true`;
  из `oidc_callback` → `false`.
- `generate_service_token(...)` — **всегда `is_local = false`** (см. ниже).

Хелперы на `Claims`:
- `is_service()` — уже есть.
- `is_local_admin() -> bool` = `!is_service() && role == Admin && is_local`.

Четыре класса актора:

| Класс | Условие |
|---|---|
| **Local admin** | `!service && role==Admin && is_local` |
| **OIDC admin** | `!service && role==Admin && !is_local` |
| **User** | `!service && role==User` |
| **Service** | `is_service()` — токен `role=User`, `id=owner`, всегда user-класс |

Сервисные токены (`generate_service_token`) уже жёстко несут `role=User` и
`id=owner_user_id`. Токены stateless (вне JTI-store, переживают рестарт).
Решение: SA **никогда** не наследуют admin-класс владельца — всегда user-класс,
дополнительно суженный скоупами. Поэтому `is_local=false` для SA.

## Матрица доступа

«свои» = `cert.user_id == claims.id`. «групповые» = существует группа, где состоят
и пользователь (`claims.id`), и сертификат.

| Актор | Список (видит) | Download pkcs12+ключ / пароль | Delete / Revoke | Управление группами |
|---|---|---|---|---|
| **Local admin** | всё | всё | всё | **да** |
| **OIDC admin** | свои + групповые | свои + групповые (с ключами) | только свои | нет |
| **User** | свои + групповые | только свои | только свои | нет |
| **Service** (scope) | свои + групповые | только свои | нет (нет scope) | нет |

Create / Import: доступны **любому** аутентифицированному актору (см. ниже).

## Схема БД — миграция `15-groups`

`backend/migrations/15-groups/up.sql`:

```sql
CREATE TABLE groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_on  INTEGER NOT NULL
);

CREATE TABLE group_users (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE group_certificates (
    group_id       INTEGER NOT NULL REFERENCES groups(id)            ON DELETE CASCADE,
    certificate_id INTEGER NOT NULL REFERENCES user_certificates(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, certificate_id)
);
```

`down.sql` дропает три таблицы. `ON DELETE CASCADE` снимает членство автоматически
при удалении группы / пользователя / сертификата.

## Backend

### `data/objects.rs`
- `struct Group { id, name, description, created_on }`
- `struct GroupDetail { group: Group, user_ids: Vec<i64>, certificate_ids: Vec<i64> }`

### `auth/session_auth.rs`
- Поле `is_local` в `Claims` + хелпер `is_local_admin()`.
- Новый guard `AuthenticatedLocalAdmin`: `authenticate → !is_service && role==Admin
  && is_local`, иначе `Forbidden`. Реализация через существующий `impl_openapi_auth!`.
- Сигнатуры `generate_token`/`generate_service_token` дополняются `is_local`.

### `db.rs` — новые методы
- CRUD групп: `insert_group`, `get_all_groups`, `get_group_detail`, `update_group`,
  `delete_group`.
- Состав (replace-семантика в одной транзакции): `set_group_users(id, &[i64])`,
  `set_group_certs(id, &[i64])`.
- `get_visible_certs(user_id) -> Vec<Certificate>`:

  ```sql
  SELECT DISTINCT c.<columns> FROM user_certificates c
  WHERE c.user_id = ?1
     OR c.id IN (
        SELECT gc.certificate_id FROM group_certificates gc
        JOIN group_users gu ON gu.group_id = gc.group_id
        WHERE gu.user_id = ?1)
  ```
  (не изменяем `get_user_certs` — он нужен для CRL/CA-фильтров.)
- `user_shares_group_with_cert(user_id, cert_id) -> bool` — для проверки download
  OIDC-админом.

### `api.rs` — изменения эндпоинтов
- `get_certificates`: `is_local_admin()` → всё; иначе → `get_visible_certs(claims.id)`
  (это ветвь для OIDC-admin, user и service). Service дополнительно требует `cert:read`.
- `download_certificate` + `fetch_certificate_password`: заменить текущую проверку
  на матрицу:
  - local admin → разрешить;
  - OIDC admin → `cert.user_id==id || user_shares_group_with_cert(...)`;
  - user / service → `cert.user_id==id` (service ещё требует `cert:read`).
- `create_user_certificate`: убрать `role != Admin → Forbidden`. Владелец:
  `is_local_admin()` → `payload.user_id` (любой); иначе форс `payload.user_id = claims.id`.
  Service-ветка (`cert:issue`, форс owner) без изменений.
- `import_certificate`: guard `AuthenticatedPrivileged → Authenticated`; та же логика
  выбора владельца, что и в create.
- `delete_user_cert` + `revoke_certificate`: guard `AuthenticatedPrivileged →
  Authenticated`; внутри разрешить если `is_local_admin() || (cert.user_id==claims.id
  && !is_service())`, иначе `Forbidden`.
- **Новые роуты под `AuthenticatedLocalAdmin`**:
  `GET /groups`, `POST /groups`, `GET /groups/<id>`, `PUT /groups/<id>`,
  `DELETE /groups/<id>`, `PUT /groups/<id>/users`, `PUT /groups/<id>/certificates`.

### CA-операции
`create_ca` / `import_ca` / `delete_ca` — понижаются до `AuthenticatedLocalAdmin`
(генерация/удаление корня — полномочие локального админа). Автоимпорт CA из цепочки
внутри `import_certificate` остаётся частью импорт-флоу и доступен импортирующему.

### `lib.rs`
Примонтировать новые `/groups`-роуты в openapi mount (обе точки монтирования, как
для существующих роутов).

## Frontend

- `api/groups.ts` — клиент (CRUD + `setUsers`/`setCertificates`).
- `stores/groups.ts` — pinia store по образцу `users.ts`/`acme.ts`.
- `components/GroupsTab.vue` — вкладка (по образцу `UserTab.vue`): список групп,
  создание/редактирование (name/description), два мультиселекта — участники (users)
  и сертификаты. Показывается только локальному админу.
- `router/router.ts` + `Sidebar.vue` — пункт «Groups», guard по локальному админу.
  Признак локального админа на фронте — из `auth` store (`GET /auth/me` должен отдавать
  флаг; при отсутствии — добавить в ответ `is_local`/`is_local_admin`).
- `OverviewTab.vue` — скрывать кнопки download/пароль для чужого группового серта
  (иначе UI даст 403 от API). Признак «свой» — сравнение `user_id` с текущим.
- Локали `locales/en.json`, `locales/es.json` — ключи `groups.*`.

## Тесты (backend)

- `get_visible_certs`: user видит свой без группы; видит чужой через общую группу;
  НЕ видит чужой без общей группы.
- `download_certificate` / `fetch_certificate_password` по матрице:
  - user качает свой → 200; чужой групповой → 403;
  - OIDC admin качает групповой чужой → 200; вне групп/не свой → 403;
  - local admin качает любой → 200;
  - service вне scope → 403.
- `delete`/`revoke`: владелец-человек свой → 200; чужой → 403; local admin любой → 200.
- Guard `/groups`: OIDC-admin и service → 403; local admin → 200.
- `create`/`import` обычным user форсит `user_id = claims.id`; local admin может
  задать произвольного владельца.
- `Claims` со старым токеном (`is_local` отсутствует) декодируется в `is_local=false`.

## Открытые допущения (зафиксированы, не блокируют)

- SA delete/revoke запрещены (нет соответствующего scope) — вернётся при появлении
  scope `cert:revoke`/`cert:delete`.
- `is_local` в JWT живёт до истечения токена (1 час): смена локальный↔OIDC вступает
  в силу после перелогина. Приемлемо для 1-часового TTL.
