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
async fn management_requires_admin() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await;
    let resp = client.get("/users/1/service-accounts").dispatch().await;
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
