use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Header, Status};
use serde_json::{json, Value};

/// Создаёт сервисный аккаунт с cert:read и возвращает (client_id, secret).
async fn service_credentials(client: &VaulTLSClient) -> (String, String) {
    let resp = client
        .post("/users/1/service-accounts")
        .header(ContentType::JSON)
        .body(r#"{"name":"agent-monitor","scopes":["cert:read"]}"#)
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let v: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    (
        v["client_id"].as_str().unwrap().to_string(),
        v["secret"].as_str().unwrap().to_string(),
    )
}

async fn service_token(client: &VaulTLSClient, client_id: &str, secret: &str) -> String {
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

fn heartbeat_body(agent_id: &str, version: &str) -> String {
    json!({
        "agent_id": agent_id,
        "version": version,
        "hostname": "web-01.example",
        "os": "linux",
        "arch": "amd64",
        "schedule": "0 3 1 * *",
        "heartbeat_interval_sec": 300,
        "ca_trust_enabled": false,
        "domains": [
            {
                "name": "ok.example",
                "cert_id": 7,
                "target": "file",
                "destination": "/etc/ssl/vaultls/ok.example",
                "status": "ok",
                "serial": "ABCD",
                "expiry_ms": 4102444800000_i64,
                "last_check_ms": 1700000000000_i64
            },
            {
                "name": "bad.example",
                "cert_id": 8,
                "target": "file",
                "destination": "/etc/ssl/vaultls/bad.example",
                "status": "error",
                "stage": "download",
                "error": "boom",
                "last_check_ms": 1700000000000_i64
            }
        ]
    })
    .to_string()
}

#[tokio::test]
async fn heartbeat_upserts_and_lists_for_every_human() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // admin, user id 1
    let (client_id, secret) = service_credentials(&client).await;
    let token = service_token(&client, &client_id, &secret).await;
    let bearer = Header::new("Authorization", format!("Bearer {token}"));

    // Первый heartbeat создаёт строку, второй с новой версией обновляет её же.
    let r1 = client
        .post("/agents/heartbeat")
        .header(ContentType::JSON)
        .header(bearer.clone())
        .body(heartbeat_body("uuid-1", "0.8.0"))
        .dispatch()
        .await;
    assert_eq!(r1.status(), Status::Ok);
    let r2 = client
        .post("/agents/heartbeat")
        .header(ContentType::JSON)
        .header(bearer.clone())
        .body(heartbeat_body("uuid-1", "0.8.1"))
        .dispatch()
        .await;
    assert_eq!(r2.status(), Status::Ok);

    let resp = client.get("/agents").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let list: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1, "same agent must update, not duplicate: {list}");
    let row = &arr[0];
    assert_eq!(row["version"], "0.8.1");
    assert_eq!(row["agent_uuid"], "uuid-1");
    assert_eq!(row["hostname"], "web-01.example");
    assert_eq!(row["online"], true);
    // Сводный статус считается на сервере по отчёту доменов.
    assert_eq!(row["status"], "error");
    assert_eq!(row["error_count"], 1);
    assert!(row["last_error"].as_str().unwrap().contains("bad.example"));
    assert_eq!(row["soonest_expiry_ms"], 4102444800000_i64);
    assert_eq!(row["account_name"], "agent-monitor");
    assert!(!row["owner_login"].as_str().unwrap().is_empty());
    assert_eq!(row["domains"].as_array().unwrap().len(), 2);

    // Обычный пользователь тоже видит дашборд (без прав администратора).
    // Тестовые клиенты живут каждый со своей БД, поэтому проверяем доступ,
    // а не содержимое: 200 и пустой список вместо 403.
    let plain = VaulTLSClient::new_authenticated_unprivileged().await;
    let resp = plain.get("/agents").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert!(body.as_array().unwrap().is_empty());

    // Разные agent_id у того же аккаунта — отдельные агенты (несколько хостов).
    let r3 = client
        .post("/agents/heartbeat")
        .header(ContentType::JSON)
        .header(bearer.clone())
        .body(heartbeat_body("uuid-2", "0.8.1"))
        .dispatch()
        .await;
    assert_eq!(r3.status(), Status::Ok);
    let resp = client.get("/agents").dispatch().await;
    let list: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(list.as_array().unwrap().len(), 2);

    Ok(())
}

#[tokio::test]
async fn heartbeat_rejects_human_session() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let resp = client
        .post("/agents/heartbeat")
        .header(ContentType::JSON)
        .body(heartbeat_body("uuid-1", "0.8.0"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn agents_list_rejects_service_token() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (client_id, secret) = service_credentials(&client).await;
    let token = service_token(&client, &client_id, &secret).await;
    let resp = client
        .get("/agents")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn heartbeat_rejects_bad_agent_id() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (client_id, secret) = service_credentials(&client).await;
    let token = service_token(&client, &client_id, &secret).await;
    let resp = client
        .post("/agents/heartbeat")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .body(heartbeat_body("   ", "0.8.0"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::BadRequest);
    // Без аутентификации — 401 ещё до валидации тела.
    let anon = VaulTLSClient::new().await;
    let anon = anon
        .post("/agents/heartbeat")
        .header(ContentType::JSON)
        .body(heartbeat_body("uuid-1", "0.8.0"))
        .dispatch()
        .await;
    assert_eq!(anon.status(), Status::Unauthorized);
    Ok(())
}
