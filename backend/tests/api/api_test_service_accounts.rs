use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Header, Status};
use serde_json::Value;

#[tokio::test]
async fn token_exchange_unknown_client_is_401() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let body = r#"{"client_id":"svc_does_not_exist","secret":"nope"}"#;
    let resp = client
        .post("/auth/token")
        .header(ContentType::JSON)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);
    Ok(())
}

async fn create_service_account(client: &VaulTLSClient, user_id: i64, name: &str, scopes: &[&str]) -> Value {
    let scopes_json = serde_json::to_string(scopes).unwrap();
    let body = format!(r#"{{"name":"{name}","scopes":{scopes_json}}}"#);
    let resp = client
        .post(format!("/users/{user_id}/service-accounts"))
        .header(ContentType::JSON)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    serde_json::from_str(&resp.into_string().await.unwrap()).unwrap()
}

#[tokio::test]
async fn create_lists_and_revokes_service_account() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // admin, user id 1

    let created = create_service_account(&client, 1, "ci-bot", &["cert:read"]).await;
    assert!(created["secret"].as_str().unwrap().len() == 64);
    assert!(created["client_id"].as_str().unwrap().starts_with("svc_"));
    let client_id = created["client_id"].as_str().unwrap().to_string();
    let secret = created["secret"].as_str().unwrap().to_string();
    let sid = created["id"].as_i64().unwrap();

    // List returns it without a secret
    let resp = client.get("/users/1/service-accounts").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let list_body = resp.into_string().await.unwrap();
    assert!(list_body.contains("ci-bot"));
    assert!(!list_body.contains(&secret), "secret must never be listed");

    // Exchange works
    let token_resp = client
        .post("/auth/token")
        .header(ContentType::JSON)
        .body(format!(r#"{{"client_id":"{client_id}","secret":"{secret}"}}"#))
        .dispatch()
        .await;
    assert_eq!(token_resp.status(), Status::Ok);
    let tv: Value = serde_json::from_str(&token_resp.into_string().await.unwrap())?;
    assert_eq!(tv["token_type"], "Bearer");
    assert!(tv["access_token"].as_str().unwrap().len() > 20);

    // Revoke → exchange now fails
    let del = client.delete(format!("/service-accounts/{sid}")).dispatch().await;
    assert_eq!(del.status(), Status::Ok);
    let after = client
        .post("/auth/token")
        .header(ContentType::JSON)
        .body(format!(r#"{{"client_id":"{client_id}","secret":"{secret}"}}"#))
        .dispatch()
        .await;
    assert_eq!(after.status(), Status::Unauthorized);

    Ok(())
}

#[tokio::test]
async fn create_rejects_unknown_scope() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let resp = client
        .post("/users/1/service-accounts")
        .header(ContentType::JSON)
        .body(r#"{"name":"bad","scopes":["cert:delete"]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);
    Ok(())
}

#[tokio::test]
async fn user_cannot_touch_other_users_service_accounts() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await; // user id=2
    // чужой список
    let resp = client.get("/users/1/service-accounts").dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    // чужой аккаунт создать тоже нельзя
    let resp = client
        .post("/users/1/service-accounts")
        .header(ContentType::JSON)
        .body(r#"{"name":"steal","scopes":["cert:read"]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn user_can_self_service_read_only_account() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await; // user id=2

    // cert:issue пользователю недоступен — это права админа
    let resp = client
        .post("/users/2/service-accounts")
        .header(ContentType::JSON)
        .body(r#"{"name":"too-much","scopes":["cert:issue"]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "user не должен выдавать сервису cert:issue");

    // cert:read для себя — можно
    let created = create_service_account(&client, 2, "my-agent", &["cert:read"]).await;
    let sid = created["id"].as_i64().unwrap();

    // и виден в своём списке
    let list = client.get("/users/2/service-accounts").dispatch().await
        .into_string().await.unwrap();
    assert!(list.contains("my-agent"));

    // токен работает и ограничен правами владельца
    let token = token_for(&client, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;
    let resp = client
        .get("/certificates")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);

    // свой аккаунт можно отозвать и удалить
    assert_eq!(client.delete(format!("/service-accounts/{sid}")).dispatch().await.status(), Status::Ok);
    assert_eq!(client.delete(format!("/service-accounts/{sid}/permanent")).dispatch().await.status(), Status::Ok);
    Ok(())
}

#[tokio::test]
async fn user_cannot_revoke_foreign_service_account() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await; // local admin id=1
    admin.create_user().await?;                           // user id=2
    let created = create_service_account(&admin, 1, "admins", &["cert:read"]).await;
    let sid = created["id"].as_i64().unwrap();

    admin.switch_user().await?; // под user id=2
    assert_eq!(admin.delete(format!("/service-accounts/{sid}")).dispatch().await.status(), Status::Forbidden);
    assert_eq!(admin.delete(format!("/service-accounts/{sid}/permanent")).dispatch().await.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn service_token_cannot_manage_service_accounts() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await; // local admin id=1
    let created = create_service_account(&admin, 1, "bot", &["cert:read"]).await;
    let sid = created["id"].as_i64().unwrap();
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;
    let bearer = || Header::new("Authorization", format!("Bearer {token}"));

    // не выпускает себе новые аккаунты (эскалация до cert:issue / вечный доступ)
    let resp = admin
        .post("/users/1/service-accounts")
        .header(ContentType::JSON)
        .header(bearer())
        .body(r#"{"name":"escalated","scopes":["cert:issue"]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "сервисный токен не должен создавать сервисные аккаунты");

    // не перечисляет их
    let resp = admin.get("/users/1/service-accounts").header(bearer()).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);

    // и не отзывает/не удаляет — в том числе самого себя
    let resp = admin.delete(format!("/service-accounts/{sid}")).header(bearer()).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    let resp = admin.delete(format!("/service-accounts/{sid}/permanent")).header(bearer()).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

async fn token_for(client: &VaulTLSClient, client_id: &str, secret: &str) -> String {
    let resp = client
        .post("/auth/token")
        .header(ContentType::JSON)
        .body(format!(r#"{{"client_id":"{client_id}","secret":"{secret}"}}"#))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let v: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    v["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn service_read_requires_scope() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await;
    // account WITHOUT cert:read
    let created = create_service_account(&admin, 1, "noread", &["cert:issue"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;

    let resp = admin
        .get("/certificates")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn service_with_read_scope_lists_owner_certs() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await;
    let created = create_service_account(&admin, 1, "reader", &["cert:read"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;

    let resp = admin
        .get("/certificates")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    Ok(())
}

#[tokio::test]
async fn service_inherits_owner_group_access_to_certs() -> Result<()> {
    use serde_json::json;
    let admin = VaulTLSClient::new_authenticated().await; // local admin id=1
    admin.create_user().await?;                           // user id=2
    // серт принадлежит админу (id=1)
    let cert = admin.create_client_cert(Some(1), Some("pw".into()), None).await?;

    // группа: участник — user id=2, серт — админский
    let gid: i64 = serde_json::from_str(
        &admin.post("/groups").header(ContentType::JSON)
            .body(json!({"name":"Shared"}).to_string())
            .dispatch().await.into_string().await.unwrap(),
    )?;
    admin.put(format!("/groups/{gid}/users")).header(ContentType::JSON)
        .body(json!({"ids":[2]}).to_string()).dispatch().await;
    admin.put(format!("/groups/{gid}/certificates")).header(ContentType::JSON)
        .body(json!({"ids":[cert.id]}).to_string()).dispatch().await;

    // сервисный аккаунт user-а id=2 с правом чтения
    let created = create_service_account(&admin, 2, "agent", &["cert:read"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;
    let bearer = || Header::new("Authorization", format!("Bearer {token}"));

    // серт виден в списке
    let list = admin.get("/certificates").header(bearer()).dispatch().await
        .into_string().await.unwrap();
    assert!(list.contains(&cert.id.to_string()), "групповой серт должен быть виден сервисному аккаунту");

    // и скачивается — ровно те же права на чтение, что у владельца сервиса
    let resp = admin.get(format!("/certificates/{}/download", cert.id)).header(bearer()).dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "сервис должен качать групповой серт своего владельца");

    let resp = admin.get(format!("/certificates/{}/password", cert.id)).header(bearer()).dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "сервис должен получать пароль группового серта");

    // но управлять им по-прежнему нельзя
    let resp = admin.post(format!("/certificates/{}/revoke", cert.id)).header(bearer()).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    let resp = admin.delete(format!("/certificates/{}", cert.id)).header(bearer()).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn service_cannot_reach_certs_outside_owner_groups() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await; // local admin id=1
    admin.create_user().await?;                           // user id=2
    // серт админа, ни в какой группе не состоит
    let cert = admin.create_client_cert(Some(1), Some("pw".into()), None).await?;

    let created = create_service_account(&admin, 2, "outsider", &["cert:read"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;

    let resp = admin
        .get(format!("/certificates/{}/download", cert.id))
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "сервис не должен качать серты вне групп владельца");
    Ok(())
}

#[tokio::test]
async fn service_issue_binds_to_owner() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await;
    // second user (id 2) so we can attempt to issue for someone else
    admin.create_user().await?;
    // service owned by user 1, with cert:issue
    let created = create_service_account(&admin, 1, "issuer", &["cert:issue"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;

    // Try to issue for user 2 — must be forced to owner (user 1)
    let body = r#"{"cert_name":{"cn":"svc-cert"},"user_id":2,"system_generated_password":false,"cert_type":0}"#;
    let resp = admin
        .post("/certificates")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let v: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(v["user_id"].as_i64().unwrap(), 1, "service must issue for its owner, not user 2");
    Ok(())
}

#[tokio::test]
async fn non_bearer_authorization_header_falls_back_to_cookie() -> Result<()> {
    use rocket::http::Header;
    let client = VaulTLSClient::new_authenticated().await; // admin, cookie set
    let resp = client
        .get("/certificates")
        .header(Header::new("Authorization", "Basic dXNlcjpwYXNz"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok, "non-Bearer Authorization must not break cookie auth");
    Ok(())
}

#[tokio::test]
async fn service_token_cannot_change_password() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await;
    let created = create_service_account(&admin, 1, "tok", &["cert:read"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;
    let resp = admin
        .post("/auth/change_password")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .body(r#"{"new_password":"hacked"}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "service token must not change the owner's password");
    Ok(())
}

#[tokio::test]
async fn service_token_cannot_update_user() -> Result<()> {
    let admin = VaulTLSClient::new_authenticated().await;
    let created = create_service_account(&admin, 1, "tok2", &["cert:read"]).await;
    let token = token_for(&admin, created["client_id"].as_str().unwrap(), created["secret"].as_str().unwrap()).await;
    let resp = admin
        .put("/users/1")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .body(r#"{"id":1,"name":"hacked","email":"x@y.z","has_password":true,"role":0}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden, "service token must not update the owner");
    Ok(())
}

#[tokio::test]
async fn permanent_delete_removes_service_account() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let created = create_service_account(&client, 1, "to-delete", &["cert:read"]).await;
    let sid = created["id"].as_i64().unwrap();

    let del = client.delete(format!("/service-accounts/{sid}/permanent")).dispatch().await;
    assert_eq!(del.status(), Status::Ok);

    let resp = client.get("/users/1/service-accounts").dispatch().await;
    let body = resp.into_string().await.unwrap();
    assert!(!body.contains("to-delete"), "permanently deleted account must not appear in the list");

    Ok(())
}

#[tokio::test]
async fn delete_of_unknown_service_account_is_404() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let resp = client.delete("/service-accounts/999/permanent").dispatch().await;
    assert_eq!(resp.status(), Status::NotFound);
    Ok(())
}
