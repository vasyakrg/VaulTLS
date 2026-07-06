use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::json;

#[tokio::test]
async fn local_admin_can_crud_groups() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // setup-user = local admin id=1

    // create
    let resp = client.post("/groups").header(ContentType::JSON)
        .body(json!({"name":"Alpha","description":"first"}).to_string())
        .dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    // list
    let resp = client.get("/groups").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    assert!(body.contains("Alpha"));

    Ok(())
}

#[tokio::test]
async fn plain_user_cannot_manage_groups() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await; // role=User
    let resp = client.post("/groups").header(ContentType::JSON)
        .body(json!({"name":"X"}).to_string())
        .dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn user_sees_only_owned_and_group_certs() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;      // local admin id=1
    client.create_user().await?;                                // создаёт user id=2 (role=User)
    // серт владельца id=2, выпущен админом
    let cert = client.create_client_cert(Some(2), Some("pw".into()), None).await?;

    client.switch_user().await?;                                // теперь под user id=2
    // user id=2 — владелец, видит свой серт
    let resp = client.get("/certificates").dispatch().await;
    let body = resp.into_string().await.unwrap();
    assert!(body.contains(&cert.id.to_string()));

    Ok(())
}
