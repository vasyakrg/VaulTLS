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

    // новый leaf с тем же CN, подписанный тем же CA
    let (new_leaf, new_key) =
        crate::common::helper::leaf_signed_by_pem("rotate.example.com", &ca_pem, &ca_key_pem);

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

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("history.example.com", &ca_pem, &ca_key_pem);
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

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("purge.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER8";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 2);
    client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;

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

#[tokio::test]
async fn superseded_serial_still_validates() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (id, ca_pem, ca_key_pem) = import_leaf(&client, "validate.example.com", 1).await;

    let versions: Value = serde_json::from_str(
        &client.get(format!("/certificates/{id}/versions")).dispatch().await
            .into_string().await.unwrap())?;
    let old_serial = versions.as_array().unwrap()[0]["serial_hex"].as_str().unwrap().to_string();

    let (leaf, key) = crate::common::helper::leaf_signed_by_pem("validate.example.com", &ca_pem, &ca_key_pem);
    let boundary = "VER9";
    let body = multipart_replace(boundary, &leaf, &key, &ca_pem, 1);
    client.put(format!("/certificates/{id}"))
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body).dispatch().await;

    let status: Value = serde_json::from_str(
        &client.get(format!("/certificates/validate?serial={old_serial}")).dispatch().await
            .into_string().await.unwrap())?;
    assert_ne!(status["status"].as_str(), Some("unknown"), "вытесненный серийник обязан находиться");
    assert_eq!(status["superseded"].as_bool(), Some(true));
    Ok(())
}
