use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Header, Status};
use serde_json::Value;

/// Импортирует leaf и возвращает (id сертификата, ca_pem, ca_key_pem).
/// Ключ CA возвращается, чтобы тест мог подписать им новый leaf для замены.
async fn import_leaf(client: &VaulTLSClient, cn: &str, user_id: i64) -> (i64, Vec<u8>, Vec<u8>) {
    let (ca_pem, ca_key_pem) = crate::common::helper::self_signed_ca_pem("Versions CA");
    let (leaf_pem, leaf_key_pem) = crate::common::helper::leaf_signed_by_pem(cn, &ca_pem, &ca_key_pem);

    let boundary = "VER1";
    let body = crate::common::helper::multipart_import_leaf(boundary, &leaf_pem, &leaf_key_pem, &ca_pem, user_id);
    let resp = client
        .post("/certificates/import")
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let v: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    (v["id"].as_i64().unwrap(), ca_pem, ca_key_pem)
}

/// Формирует multipart-тело для PUT: cert + key + chain.
fn multipart_replace(boundary: &str, cert_pem: &[u8], key_pem: &[u8], chain_pem: &[u8], user_id: i64) -> Vec<u8> {
    crate::common::helper::multipart_import_leaf(boundary, cert_pem, key_pem, chain_pem, user_id)
}

#[tokio::test]
async fn replacing_imported_cert_keeps_id_and_bumps_version() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "rotate.example.com", 1).await;

    let before: Value = serde_json::from_str(
        &client.get("/certificates").dispatch().await.into_string().await.unwrap())?;
    let old_fp = before.as_array().unwrap().iter()
        .find(|c| c["id"].as_i64() == Some(id)).unwrap()["fingerprint"].as_str().unwrap().to_string();

    // новый leaf с тем же CN, подписанный тем же CA; живёт дольше исходного (+90d),
    // иначе замена отклоняется как «не улучшение» (см. новую проверку в update_certificate).
    let (new_leaf, new_key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "rotate.example.com", &ca_pem, &ca_key_pem, 0, 200);

    let boundary = "VER2";
    let body = multipart_replace(boundary, &new_leaf, &new_key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let updated: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(updated["id"].as_i64(), Some(id), "id обязан сохраниться");
    assert_eq!(updated["version"].as_i64(), Some(2));
    assert_ne!(updated["fingerprint"].as_str().unwrap(), old_fp, "отпечаток обязан смениться");
    Ok(())
}

#[tokio::test]
async fn replacing_with_different_cn_is_rejected() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "same.example.com", 1).await;

    let (other_leaf, other_key) =
        crate::common::helper::leaf_signed_by_pem("other.example.com", &ca_pem, &ca_key_pem);

    let boundary = "VER3";
    let body = multipart_replace(boundary, &other_leaf, &other_key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);
    Ok(())
}

#[tokio::test]
async fn replacing_internally_issued_cert_is_rejected() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    // выпущен внутренним CA — is_imported = 0
    let cert = client.create_client_cert(Some(1), Some("pw".into()), None).await?;

    let (ca_pem, ca_key_pem) = crate::common::helper::self_signed_ca_pem("Foreign CA");
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("whatever", &ca_pem, &ca_key_pem);

    let boundary = "VER4";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{}", cert.id))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);
    Ok(())
}

#[tokio::test]
async fn group_member_may_read_but_not_replace() -> Result<()> {
    use serde_json::json;
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "shared.example.com", 1).await;

    let gid: i64 = serde_json::from_str(
        &client.post("/groups").header(ContentType::JSON)
            .body(json!({"name":"Shared"}).to_string())
            .dispatch().await.into_string().await.unwrap())?;
    client.put(format!("/groups/{gid}/users")).header(ContentType::JSON)
        .body(json!({"ids":[2]}).to_string()).dispatch().await;
    client.put(format!("/groups/{gid}/certificates")).header(ContentType::JSON)
        .body(json!({"ids":[id]}).to_string()).dispatch().await;

    client.switch_user().await?; // под user id=2

    assert_eq!(client.get(format!("/certificates/{id}/versions")).dispatch().await.status(), Status::Ok);

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("shared.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER5";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 2);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "участник группы читает, но не заменяет");
    Ok(())
}

#[tokio::test]
async fn service_token_needs_issue_scope_to_replace() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await; // local admin id=1
    let (id, ca_pem, ca_key_pem) = import_leaf(&admin, "svc.example.com", 1).await;

    let created: Value = serde_json::from_str(
        &admin.post("/users/1/service-accounts").header(ContentType::JSON)
            .body(r#"{"name":"rot","scopes":["cert:read"]}"#)
            .dispatch().await.into_string().await.unwrap())?;
    let token: Value = serde_json::from_str(
        &admin.post("/auth/token").header(ContentType::JSON)
            .body(format!(r#"{{"client_id":"{}","secret":"{}"}}"#,
                created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()))
            .dispatch().await.into_string().await.unwrap())?;
    let bearer = format!("Bearer {}", token["access_token"].as_str().unwrap());

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("svc.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER6";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = admin
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .header(Header::new("Authorization", bearer))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "cert:read не даёт права заменять");
    Ok(())
}

#[tokio::test]
async fn old_version_stays_downloadable_after_replace() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "history.example.com", 1).await;

    let v1 = client.get(format!("/certificates/{id}/download")).dispatch().await
        .into_bytes().await.unwrap();

    // живёт дольше исходного (+90d), иначе замена отклоняется как «не улучшение».
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "history.example.com", &ca_pem, &ca_key_pem, 0, 200);
    let boundary = "VER7";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    let v2 = client.get(format!("/certificates/{id}/download")).dispatch().await
        .into_bytes().await.unwrap();
    assert_ne!(v1, v2, "текущая версия сменилась");

    let v1_again = client.get(format!("/certificates/{id}/download?version=1")).dispatch().await
        .into_bytes().await.unwrap();
    assert_eq!(v1, v1_again, "первая версия доступна по номеру");

    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    let arr = versions.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["version"].as_i64(), Some(2));
    assert_eq!(arr[0]["current"].as_bool(), Some(true));
    assert!(arr[0]["version_id"].is_null());
    assert_eq!(arr[1]["version"].as_i64(), Some(1));
    assert!(arr[1]["version_id"].as_i64().unwrap() > 0);
    Ok(())
}

#[tokio::test]
async fn unknown_version_is_404() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, _ca_pem, _ca_key) = import_leaf(&client, "single.example.com", 1).await;
    let resp = client.get(format!("/certificates/{id}/download?version=7")).dispatch().await;
    assert_eq!(resp.status(), Status::NotFound);
    Ok(())
}

#[tokio::test]
async fn only_local_admin_deletes_historical_versions() -> Result<()> {
    use crate::common::constants::{TEST_PASSWORD, TEST_USER_EMAIL};

    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "purge.example.com", 2).await;

    // живёт дольше исходного (+90d), иначе замена отклоняется как «не улучшение».
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "purge.example.com", &ca_pem, &ca_key_pem, 0, 200);
    let boundary = "VER8";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 2);
    let replace_resp = client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;
    assert_eq!(replace_resp.status(), Status::Ok, "замена обязана пройти — иначе второй версии не будет");

    // текущую версию удалить нельзя
    assert_eq!(client.delete(format!("/certificates/{id}/versions/2")).dispatch().await.status(),
               Status::BadRequest);

    // владелец без прав локального админа — 403
    client.switch_user().await?; // user id=2, он же владелец
    assert_eq!(client.delete(format!("/certificates/{id}/versions/1")).dispatch().await.status(),
               Status::Forbidden);

    // локальный админ — 200, версия исчезает из истории
    client.logout().await?;
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await?;
    assert_eq!(client.delete(format!("/certificates/{id}/versions/1")).dispatch().await.status(),
               Status::Ok);

    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    assert_eq!(versions.as_array().unwrap().len(), 1, "осталась только текущая версия");
    Ok(())
}

/// Отозванный сертификат заменять нельзя: иначе CRL перечислит новый серийник,
/// а скомпрометированный старый молча снова станет валидным.
/// Гонку `/revoke` с `PUT` тест не воспроизводит — её закрывает условие в UPDATE
/// (см. db::tests::replace_certificate_refuses_revoked_row); здесь проверяется
/// предварительная проверка обработчика.
#[tokio::test]
async fn revoked_cert_cannot_be_replaced() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1

    // CA импортируется вместе с ключом: без него /revoke упирается в «нет ключа — нет CRL»
    // и до интересующей нас проверки дело не доходит.
    let (ca_pem, ca_key_pem) = crate::common::helper::self_signed_ca_pem("Revoke CA");
    let ca_body = crate::common::helper::multipart_two_files(
        "CAB1", "ca_cert", "ca.pem", &ca_pem, "ca_key", "ca.key", &ca_key_pem);
    assert_eq!(
        client.post("/certificates/ca/import")
            .header(ContentType::new("multipart", "form-data").with_params(("boundary", "CAB1")))
            .body(ca_body).dispatch().await.status(),
        Status::Ok);

    let (leaf_pem, leaf_key_pem) =
        crate::common::helper::leaf_signed_by_pem("revoked.example.com", &ca_pem, &ca_key_pem);
    let import_body = crate::common::helper::multipart_import_leaf("VER10I", &leaf_pem, &leaf_key_pem, &ca_pem, 1);
    let imported = client.post("/certificates/import")
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", "VER10I")))
        .body(import_body).dispatch().await;
    assert_eq!(imported.status(), Status::Ok);
    let id = serde_json::from_str::<Value>(&imported.into_string().await.unwrap())?["id"]
        .as_i64().unwrap();

    let revoke = client.post(format!("/certificates/{id}/revoke")).dispatch().await;
    assert_eq!(revoke.status(), Status::Ok);

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("revoked.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER10";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest, "отозванный сертификат не подлежит замене");

    // содержимое осталось прежним: версия не выросла, история пуста
    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    let arr = versions.as_array().unwrap();
    assert_eq!(arr.len(), 1, "замена не должна была создать историческую версию");
    assert_eq!(arr[0]["version"].as_i64(), Some(1));
    Ok(())
}

/// Заменять живой сертификат уже истёкшим нельзя: агент задеплоит его на
/// следующем поллинге, и сервис на этом хосте перестанет работать сразу же.
#[tokio::test]
async fn replacing_with_expired_leaf_is_rejected() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "expired.example.com", 1).await;

    // not_before = -10d, not_after = -1d: уже истёк.
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "expired.example.com", &ca_pem, &ca_key_pem, -10, -1);

    let boundary = "VER11";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest, "просроченный сертификат не подлежит замене");
    let msg = resp.into_string().await.unwrap();
    assert!(msg.contains("expired"), "сообщение обязано упоминать истечение срока: {msg}");
    Ok(())
}

/// Заменять сертификат тем, что ещё не вступил в силу, нельзя: агент задеплоит
/// его на следующем поллинге, и сервис будет падать до наступления not_before.
#[tokio::test]
async fn replacing_with_not_yet_valid_leaf_is_rejected() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "future.example.com", 1).await;

    // not_before = +10d, not_after = +100d: ещё не наступил.
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "future.example.com", &ca_pem, &ca_key_pem, 10, 100);

    let boundary = "VER12";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest, "ещё не вступивший в силу сертификат не подлежит замене");
    let msg = resp.into_string().await.unwrap();
    assert!(msg.contains("valid"), "сообщение обязано упоминать момент вступления в силу: {msg}");
    Ok(())
}

/// Заменять сертификат тем, что не продлевает срок действия, бессмысленно и почти
/// всегда — ошибка оператора (случайно взят несвежий файл).
#[tokio::test]
async fn replacing_with_non_improving_leaf_is_rejected() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    // import_leaf использует leaf_signed_by_pem: valid_until = +90d от текущего момента.
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "same-expiry.example.com", 1).await;

    // Валиден (not_before <= now < not_after), но истекает раньше существующего (+90d).
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "same-expiry.example.com", &ca_pem, &ca_key_pem, 0, 30);

    let boundary = "VER13";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest, "замена без улучшения срока действия отклоняется");
    let msg = resp.into_string().await.unwrap();
    assert!(msg.contains("no later than"),
        "сообщение обязано указывать на отсутствие улучшения срока действия (а не на другую причину отказа): {msg}");
    Ok(())
}

/// Положительный контроль: leaf, который валиден и живёт дольше текущего,
/// обязан пройти все три новые проверки и заменить сертификат успешно.
#[tokio::test]
async fn replacing_with_longer_lived_leaf_succeeds() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    // import_leaf: valid_until = +90d от текущего момента.
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "longer.example.com", 1).await;

    // Валиден сейчас и живёт дольше (+200d > +90d).
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "longer.example.com", &ca_pem, &ca_key_pem, 0, 200);

    let boundary = "VER14";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client
        .put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok, "более долгоживущий валидный сертификат обязан пройти замену");
    let updated: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(updated["version"].as_i64(), Some(2));
    Ok(())
}

#[tokio::test]
async fn superseded_serial_still_validates() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "validate.example.com", 1).await;

    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    let old_serial = versions.as_array().unwrap()[0]["serial_hex"].as_str().unwrap().to_string();

    // живёт дольше исходного (+90d), иначе замена отклоняется как «не улучшение».
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "validate.example.com", &ca_pem, &ca_key_pem, 0, 200);
    let boundary = "VER9";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let replace_resp = client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;
    assert_eq!(replace_resp.status(), Status::Ok, "замена обязана пройти — иначе серийник не станет superseded");

    let status: Value = serde_json::from_str(
        &client.get(format!("/certificates/validate?serial={old_serial}")).dispatch().await
            .into_string().await.unwrap())?;
    assert_ne!(status["status"].as_str(), Some("unknown"), "вытесненный серийник обязан находиться");
    assert_eq!(status["superseded"].as_bool(), Some(true));
    Ok(())
}

/// Импортированный сертификат, уже отдавший своё единственное предупреждение
/// (watch_expiry гасит renew_method после уведомления), обязан снова начать
/// предупреждать после ручной замены: именно ради этой замены endpoint и создан,
/// и другого способа переставить renew_method у существующей записи в API нет.
#[tokio::test]
async fn replace_rearms_a_muted_imported_certificate() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    // import_leaf не передаёт renew_method — запись создаётся с None (0), ровно как
    // строка, которую watch_expiry уже погасил после единственного письма.
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "muted.example.com", 1).await;

    let renew_method_of = |v: &Value, id: i64| -> i64 {
        v.as_array().unwrap().iter()
            .find(|c| c["id"].as_i64() == Some(id)).unwrap()["renew_method"].as_i64().unwrap()
    };
    let before: Value = serde_json::from_str(
        &client.get("/certificates").dispatch().await.into_string().await.unwrap())?;
    assert_eq!(renew_method_of(&before, id), 0, "исходная запись немая — это и есть баг-сценарий");

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "muted.example.com", &ca_pem, &ca_key_pem, 0, 200);
    let boundary = "VER15";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    let resp = client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    let after: Value = serde_json::from_str(
        &client.get("/certificates").dispatch().await.into_string().await.unwrap())?;
    assert_eq!(renew_method_of(&after, id), 1,
        "замена обязана перевзвести уведомления (None → Notify), иначе серт молчит навсегда");

    // Явно присланный renew_method побеждает: оператор ставит RenewAndNotify (3).
    let (leaf2, key2) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "muted.example.com", &ca_pem, &ca_key_pem, 0, 300);
    let boundary = "VER16";
    let body = crate::common::helper::multipart_import_leaf_with_fields(
        boundary, &leaf2, &key2, &ca_pem, 1, &[("renew_method", "3")]);
    let resp = client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    let after2: Value = serde_json::from_str(
        &client.get("/certificates").dispatch().await.into_string().await.unwrap())?;
    assert_eq!(renew_method_of(&after2, id), 3, "явный renew_method обязан быть учтён");
    Ok(())
}

/// История отозванного сертификата — источник его серийников для CRL и для
/// /certificates/validate. Удалить старую версию значит снять скомпрометированный
/// серийник с отзыва.
#[tokio::test]
async fn revoked_certificate_history_cannot_be_deleted() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1

    // CA с ключом: без него /revoke упирается в «нет ключа — нет CRL».
    let (ca_pem, ca_key_pem) = crate::common::helper::self_signed_ca_pem("Revoke History CA");
    let ca_body = crate::common::helper::multipart_two_files(
        "CAB2", "ca_cert", "ca.pem", &ca_pem, "ca_key", "ca.key", &ca_key_pem);
    assert_eq!(
        client.post("/certificates/ca/import")
            .header(ContentType::new("multipart", "form-data").with_params(("boundary", "CAB2")))
            .body(ca_body).dispatch().await.status(),
        Status::Ok);

    let (leaf_pem, leaf_key_pem) =
        crate::common::helper::leaf_signed_by_pem("revoked-history.example.com", &ca_pem, &ca_key_pem);
    let import_body = crate::common::helper::multipart_import_leaf("VER17I", &leaf_pem, &leaf_key_pem, &ca_pem, 1);
    let imported = client.post("/certificates/import")
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", "VER17I")))
        .body(import_body).dispatch().await;
    assert_eq!(imported.status(), Status::Ok);
    let id = serde_json::from_str::<Value>(&imported.into_string().await.unwrap())?["id"]
        .as_i64().unwrap();

    // Замена — чтобы появилась историческая версия 1.
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "revoked-history.example.com", &ca_pem, &ca_key_pem, 0, 200);
    let boundary = "VER17";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    assert_eq!(client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await.status(), Status::Ok);

    assert_eq!(client.post(format!("/certificates/{id}/revoke")).dispatch().await.status(), Status::Ok);

    let resp = client.delete(format!("/certificates/{id}/versions/1")).dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest, "историю отозванного сертификата удалять нельзя");
    let msg = resp.into_string().await.unwrap();
    assert!(msg.contains("revoked"), "сообщение обязано объяснять причину: {msg}");

    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    assert_eq!(versions.as_array().unwrap().len(), 2, "обе версии обязаны остаться на месте");
    Ok(())
}

/// Сознательный «даунгрейд» срока: годовой сертификат меняют на свежий 90-дневный
/// после компрометации. Строка не отозвана, другого пути заменить её на месте нет —
/// поэтому локальному админу разрешён обход через force=true.
#[tokio::test]
async fn local_admin_may_force_a_shorter_lived_replacement() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "downgrade.example.com", 1).await;

    // Валиден сейчас, но истекает раньше существующего (+90d) — обычно это отказ.
    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "downgrade.example.com", &ca_pem, &ca_key_pem, 0, 30);

    let boundary = "VER18";
    let body = crate::common::helper::multipart_import_leaf_with_fields(
        boundary, &leaf, &key, &ca_pem, 1, &[("force", "true")]);
    let resp = client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "локальный админ вправе сократить срок осознанно");
    let updated: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(updated["version"].as_i64(), Some(2));

    // Обход обязан быть виден в аудите.
    let audit: Value = serde_json::from_str(
        &client.get("/audit?action=update_certificate").dispatch().await
            .into_string().await.unwrap())?;
    let detail = audit["rows"].as_array().unwrap().iter()
        .find(|r| r["target_id"].as_str() == Some(id.to_string().as_str()))
        .and_then(|r| r["detail"].as_str()).unwrap_or_default().to_string();
    assert!(detail.contains("FORCED"), "обход обязан быть записан в аудит: {detail}");
    Ok(())
}

/// force доступен только локальному админу: владельцу-обычному пользователю он
/// ничего не даёт, отказ остаётся обычным.
#[tokio::test]
async fn owner_cannot_force_a_shorter_lived_replacement() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2 — обычный
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "owner-force.example.com", 2).await;

    client.switch_user().await?; // под владельцем id=2

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "owner-force.example.com", &ca_pem, &ca_key_pem, 0, 30);
    let boundary = "VER19";
    let body = crate::common::helper::multipart_import_leaf_with_fields(
        boundary, &leaf, &key, &ca_pem, 2, &[("force", "true")]);
    let resp = client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest, "force у не-локального-админа игнорируется");
    let msg = resp.into_string().await.unwrap();
    assert!(msg.contains("no later than"), "отказ обязан остаться прежним: {msg}");
    Ok(())
}

/// force снимает ТОЛЬКО требование продлить срок. Просроченный материал ломает
/// сервис немедленно — эта проверка абсолютна для всех, включая локального админа.
#[tokio::test]
async fn force_does_not_bypass_the_expired_check() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "force-expired.example.com", 1).await;

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem_with_validity(
        "force-expired.example.com", &ca_pem, &ca_key_pem, -10, -1);
    let boundary = "VER20";
    let body = crate::common::helper::multipart_import_leaf_with_fields(
        boundary, &leaf, &key, &ca_pem, 1, &[("force", "true")]);
    let resp = client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest, "force не отменяет проверку на истечение срока");
    let msg = resp.into_string().await.unwrap();
    assert!(msg.contains("expired"), "сообщение обязано указывать на истечение срока: {msg}");
    Ok(())
}
