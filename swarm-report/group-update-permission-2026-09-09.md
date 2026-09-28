# Report: управление сертом для участников группы доступа (Update)

- **Дата:** 2026-09-09
- **Профиль:** business-feature
- **Статус:** Done

## Задача

Расширить матрицу прав замены сертификата (PUT /certificates/<id>, кнопка
«Update certificate»): раньше — локальный админ или владелец; теперь — также
участник группы, в которую расшарен серт.

Согласованные рамки (уточнены с заказчиком):

1. Владелец права **сохраняет**: итог — админ ИЛИ владелец ИЛИ участник группы.
2. Скоуп — **только Update**. Revoke/Delete остаются у владельца и локального админа
   (отзыв необратим — CRL/KRL; удаление разрушительно).
3. Сервисные токены групп не наследуют: cert:issue по-прежнему действует только
   на сертификаты своего владельца.

## Решение

**Бэкенд.** Право замены вычисляется сервером, фронт получает готовый флаг
(обычный пользователь не может сам узнать свои группы — groups API только для
локальных админов):

- `db.group_shared_cert_ids(user_id)` — батч-запрос id сертов, достижимых через
  группы пользователя (для листинга; точечный `user_shares_group_with_cert` уже был).
- `GET /certificates` теперь возвращает `CertificateListEntry { #[serde(flatten)]
  certificate, managed_via_group }` — JSON-форма для существующих клиентов не меняется.
  Для сервисных токенов флаг всегда false.
- `update_certificate`: к правилу «владелец или локальный админ» добавлен третий
  путь — `user_shares_group_with_cert(user, cert)`. Сервисная ветка не тронута.
- Владелец записи при замене не меняется (как и прежде).

**Фронт.** `Certificate.managed_via_group?` + `canUpdate`: `canManage(cert) ||
cert.managed_via_group`. Revoke/Delete по-прежнему на `canManage`. После замены
список refetch'ается целиком — флаг пересчитывается сервером.

## Изменённые файлы

| Файл | Что |
|---|---|
| `backend/src/db.rs` | `group_shared_cert_ids()` |
| `backend/src/api.rs` | `CertificateListEntry`, флаг в `GET /certificates`, группа в авторизации `update_certificate`, docstring |
| `frontend/src/types/Certificate.ts` | `managed_via_group?` |
| `frontend/src/components/OverviewTab.vue` | `canUpdate` учитывает флаг |
| `backend/tests/api/api_test_cert_versions.rs` | `group_member_may_read_but_not_replace` → `group_member_may_replace_shared_cert` (+ флаг, владелец не меняется); новый `non_member_cannot_replace_shared_cert` |

## Матрица после изменения

| Кто | Download/Password | Update (замена) | Revoke/Delete |
|---|---|---|---|
| Локальный админ | ✅ | ✅ | ✅ |
| Владелец | ✅ | ✅ | ✅ |
| Участник группы с сертом | ✅ | ✅ **новое** | ❌ |
| Сервис (cert:issue) | — | ✅ только свои | ❌ |
| Сервис (cert:read) | ✅ свои | ❌ | ❌ |
| Не-участник | ❌ (серт невидим) | ❌ | ❌ |

## Validation

- `cargo test`: unit 107 ok; integration 107 ok, 1 failure —
  `test_ssh_revocation_and_krl`, падает и на чистом main (локальный ssh-keygen
  отвечает 255 на `-Q -f krl`), предсуществующее, не связано с изменением
- `api_test_cert_versions`: 20/20, включая оба новых сценария
- frontend: vitest 36/36, `npm run build` (type-check + build) — зелёные

## Ограничения (зафиксировано осознанно)

1. Участник группы заменяет серт, но не управляет его жизненным циклом: отзыв и
   удаление — только владелец/админ.
2. Флаг `managed_via_group` вычисляется только в `GET /certificates`; ответ `PUT`
   возвращает голый `Certificate` без флага — фронт после замены делает refetch
   списка, расхождения в UI нет.
3. Участник группы видит кнопку Update, но замена по-прежнему подчиняется
   содержательным проверкам (тот же CN, не отозван, валидные сроки, продление
   срока; force — только локальный админ).
