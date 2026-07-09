use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use rocket::http::{ContentType, Status};
use serde_json::{json, Value};

#[tokio::test]
async fn audit_endpoints_require_local_admin() -> Result<()> {
    let client = VaulTLSClient::new_setup().await; // setup done, NOT logged in

    let resp = client.get("/audit").dispatch().await;
    assert_eq!(resp.status(), Status::Unauthorized);

    let resp = client.delete("/audit?before=0").dispatch().await;
    assert_eq!(resp.status(), Status::Unauthorized);

    Ok(())
}

#[tokio::test]
async fn failed_login_is_audited() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin, id=1

    // Drive a failed login on the SAME client so it hits the same in-memory DB.
    let resp = client
        .post("/auth/login")
        .header(ContentType::JSON)
        .body(json!({"email": "nobody@example.com", "password": "x"}).to_string())
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Unauthorized);

    let resp = client.get("/audit").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let page: Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    let rows = page["rows"].as_array().expect("rows array");

    let found = rows.iter().any(|r| {
        r["action"] == "login"
            && r["result"] == "failure"
            && r["actor_type"] == "anonymous"
            && r["actor_label"] == "nobody@example.com"
    });
    assert!(found, "expected a failed anonymous login row, got: {rows:?}");

    Ok(())
}

#[tokio::test]
async fn purge_removes_old_via_endpoint() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await; // local admin, id=1
    // The setup + login flow above already produced at least one audit row (login success).

    let before = client.get("/audit").dispatch().await;
    assert_eq!(before.status(), Status::Ok);
    let before_page: Value = serde_json::from_str(&before.into_string().await.unwrap())?;
    let before_rows = before_page["rows"].as_array().expect("rows array").len();
    assert!(before_rows > 0, "expected at least one audit row before purge");

    // future timestamp — purges everything recorded so far
    let future_ts = 4_102_444_800_i64; // 2100-01-01T00:00:00Z
    let resp = client
        .delete(format!("/audit?before={future_ts}"))
        .dispatch()
        .await;
    assert_eq!(resp.status(), Status::Ok);
    let purged: u64 = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert!(purged as usize >= before_rows);

    let after = client.get("/audit").dispatch().await;
    assert_eq!(after.status(), Status::Ok);
    let after_page: Value = serde_json::from_str(&after.into_string().await.unwrap())?;
    let after_rows = after_page["rows"].as_array().expect("rows array").len();
    assert!(after_rows < before_rows.max(1), "expected fewer rows after purge");

    Ok(())
}
