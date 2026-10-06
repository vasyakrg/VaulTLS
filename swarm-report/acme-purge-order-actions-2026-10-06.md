# Report: полное удаление ACME-аккаунтов и управление заказами (revoke/delete)

- **Дата:** 2026-10-06
- **Профиль:** business-feature
- **Статус:** Done

## Задача

1. Деактивированные ACME-аккаунты видны чекбоксом «показать деактивированные»,
   но удалить их совсем нельзя: существующий `DELETE /acme/accounts/<id>` на
   самом деле делает деактивацию (soft delete). Добавить локальному админу
   право на полное удаление.
2. ACME Orders создаются, но на фронте нет кнопок отзыва/удаления заказа.

## Решение

**Бэкенд** (`backend/src/acme/admin.rs`, `db.rs`, `api.rs`, `data/enums.rs`):

- `DELETE /acme/acmas/accounts` — нет, маршруты такие:
  - `DELETE /acme/accounts/<id>/purge` (`AuthenticatedLocalAdmin`) — полное
    удаление. Разрешено ТОЛЬКО для аккаунтов в статусе `deactivated`
    (активный сначала деактивируется) — защита от случайного удаления
    рабочего аккаунта. Удаляет аккаунт и все его заказы (явный DELETE +
    FK CASCADE); выпущенные сертификаты остаются, связь
    `user_certificates.acme_account_id` сбрасывается (FK SET NULL).
  - `DELETE /acme/orders/<id>` (`AuthenticatedLocalAdmin`) — удаление заказа
    (очистка истории; выданный сертификат не трогается).
  - `POST /acme/orders/<id>/revoke` (`AuthenticatedLocalAdmin`) — отзыв
    сертификата, выпущенного по заказу: `revoke_user_cert` + пересборка
    CRL/KRL CA. Повторный отзыв — 400.
- Логика отзыва сертификата вынесена из `revoke_certificate` в общий хелпер
  `revoke_cert_and_update_crl()` (api.rs) — используется и пользовательским
  маршрутом, и заказным. В хелпер добавлен guard «уже отозван» (у заказного
  отзыва и у обычного теперь повторный отзыв даёт 400 вместо повторной
  перезаписи `revoked_at`).
- Аудит: новые действия `delete_acme_account`, `delete_acme_order`
  (`AuditAction` + `as_str` + `FromStr`); отзыв через заказ пишется как
  `revoke_certificate` с detail `via ACME order #N`. Существующие
  деактивация/редактирование ACME-аккаунтов аудита не имели и не получили
  (вне скоупа).
- Права: деструктивные операции — только локальный админ (зеркалит матрицу
  сертов: revoke/delete = владелец/локальный админ); деактивация и
  редактирование остались на `AuthenticatedPrivileged`.

**Фронтенд** (`AcmeTab.vue`, `api/acme.ts`, `stores/acme.ts`, локали en/es):

- Аккаунты: для деактивированных и `isLocalAdmin` — кнопка «Delete
  permanently» с диалогом подтверждения (поясняет: заказы удалятся,
  сертификаты останутся).
- Заказы: колонка действий (только `isLocalAdmin`): «Revoke certificate»
  (видна при наличии `certificate_id`) и «Delete order», обе с
  подтверждением.
- `AuditTab.vue`: в список действий фильтра добавлены новые действия.

## Изменённые файлы

| Файл | Что |
|---|---|
| `backend/src/data/enums.rs` | `AuditAction::DeleteAcmeAccount/DeleteAcmeOrder` |
| `backend/src/db.rs` | `delete_acme_account` (с каскадом заказов), `delete_acme_order` |
| `backend/src/api.rs` | хелпер `revoke_cert_and_update_crl`, рефакторинг `revoke_certificate` |
| `backend/src/acme/admin.rs` | маршруты purge / delete-order / revoke-order + аудит |
| `backend/src/lib.rs` | регистрация маршрутов в трёх монтированиях |
| `frontend/src/api/acme.ts`, `stores/acme.ts` | `purgeAccount`, `deleteOrder`, `revokeOrder` |
| `frontend/src/components/AcmeTab.vue` | кнопки + модалки подтверждения |
| `frontend/src/components/AuditTab.vue` | новые действия в фильтре |
| `frontend/src/locales/en.json`, `es.json` | ключи `acme.purge*`, `revokeOrder*`, `deleteOrder*` |
| `backend/tests/api/api_test_acme.rs` | +2 теста (e2e через протокол) |

## Validation

- Новые тесты: `acme_purge_requires_deactivated_and_cascades_orders`
  (purge активного → 400; после деактивации → 200; аккаунт и заказы исчезли)
  и `acme_order_revoke_and_delete` — полный e2e: регистрация EAB → new-order →
  challenge (auto_validate) → finalize с CSR → сертификат выпущен → revoke
  (серт с `revoked_at`, повторный отзыв 400) → delete заказа (заказ исчез,
  сертификат остался)
- Все 5 ACME-тестов зелёные; `cargo clippy` без новых предупреждений
- frontend: `vue-tsc` + build + vitest 36/36 — зелёные
- Полный `cargo test`: 2 известных предсуществующих фейла
  (`test_version`, `test_ssh_revocation_and_krl`), новых нет

## Ограничения (зафиксировано осознанно)

1. Purge разрешён только деактивированным аккаунтам: активный нужно сначала
   деактивировать — двухшаговое удаление, случайное невозможно.
2. Удаление заказа не трогает выпущенный сертификат; серт продолжает жить
   на владельце аккаунта и отзывается/удаляется общими сертификатными
   маршрутами.
3. Пользовательский `revoke_certificate` теперь отклоняет повторный отзыв
   (400) — раньше молча перезаписывал `revoked_at` и пересобирал CRL.
4. Не-локальные админы (OIDC) сохраняют деактивацию/редактирование, но не
   получают purge/revoke/delete — деструктив, как и в матрице сертов.
