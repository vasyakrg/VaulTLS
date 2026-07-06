use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::{json, Value};

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

#[tokio::test]
async fn group_visibility_does_not_grant_download() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2
    let cert = client.create_client_cert(Some(1), Some("pw".into()), None).await?; // владелец = admin id=1

    // группа с user id=2 и сертом владельца id=1
    let gid: i64 = serde_json::from_str(&client.post("/groups").header(ContentType::JSON)
        .body(json!({"name":"Shared"}).to_string()).dispatch().await.into_string().await.unwrap())?;
    client.put(format!("/groups/{gid}/users")).header(ContentType::JSON)
        .body(json!({"ids":[2]}).to_string()).dispatch().await;
    client.put(format!("/groups/{gid}/certificates")).header(ContentType::JSON)
        .body(json!({"ids":[cert.id]}).to_string()).dispatch().await;

    client.switch_user().await?; // под user id=2

    // видит в списке (через группу)
    let list = client.get("/certificates").dispatch().await.into_string().await.unwrap();
    assert!(list.contains(&cert.id.to_string()));
    // но НЕ качает чужой серт
    let resp = client.get(format!("/certificates/{}/download", cert.id)).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    // и НЕ получает пароль
    let resp = client.get(format!("/certificates/{}/password", cert.id)).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn plain_user_can_issue_own_cert() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await; // user id=2
    // пытается выписать серт на чужой user_id=1 — должен принудительно стать своим (id=2)
    let cert = client.create_client_cert(Some(1), Some("pw".into()), None).await?;
    assert_eq!(cert.user_id, 2);
    Ok(())
}

#[tokio::test]
async fn plain_user_import_forces_owner_to_self() -> Result<()> {
    let client = VaulTLSClient::new_authenticated_unprivileged().await; // role=User, id=2

    let (ca_pem, ca_key_pem) = crate::common::helper::self_signed_ca_pem("Import Owner CA");
    let (leaf_pem, leaf_key_pem) =
        crate::common::helper::leaf_signed_by_pem("owner-test.example.com", &ca_pem, &ca_key_pem);

    let boundary = "OWN1";
    // multipart_import_leaf sends user_id: 1 (another user) — must be forced to self (2)
    let body = crate::common::helper::multipart_import_leaf(
        boundary, &leaf_pem, &leaf_key_pem, &ca_pem, 1,
    );
    let resp = client
        .post("/certificates/import")
        .header(ContentType::new("multipart", "form-data").with_params(("boundary", boundary)))
        .body(body)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let imported: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(
        imported["user_id"].as_i64(),
        Some(2),
        "owner must be forced to self (2), not the requested 1"
    );
    Ok(())
}

#[tokio::test]
async fn owner_can_delete_own_others_cannot() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin id=1
    client.create_user().await?;                           // user id=2
    let admin_cert = client.create_client_cert(Some(1), Some("pw".into()), None).await?;
    let user_cert = client.create_client_cert(Some(2), Some("pw".into()), None).await?;

    client.switch_user().await?; // user id=2
    // не владелец (серт admin) → Forbidden
    let resp = client.delete(format!("/certificates/{}", admin_cert.id)).dispatch().await;
    assert_eq!(resp.status(), Status::Forbidden);
    // свой → Ok
    let resp = client.delete(format!("/certificates/{}", user_cert.id)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    Ok(())
}
