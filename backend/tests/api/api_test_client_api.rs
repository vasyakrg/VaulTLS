use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use openssl::pkcs12::Pkcs12;
use rocket::http::{ContentType, Status};

/// Extract the lowercase-hex serial from a downloaded PKCS#12 bundle.
fn serial_hex_from_p12(p12: &[u8], password: &str) -> String {
    let parsed = Pkcs12::from_der(p12).unwrap().parse2(password).unwrap();
    let cert = parsed.cert.unwrap();
    let bn = cert.serial_number().to_bn().unwrap().to_vec();
    bn.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn validate_reports_valid_then_revoked() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let cert = client.create_client_cert(None, Some("pw".to_string()), None).await?;

    let req = client.get(format!("/certificates/{}/download", cert.id));
    let p12 = req.dispatch().await.into_bytes().await.unwrap();
    let serial = serial_hex_from_p12(&p12, "pw");

    // Valid
    let resp = client.get(format!("/certificates/validate?serial={serial}")).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_string().await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(v["status"], "valid");
    assert!(v["not_after"].is_number());
    assert!(v["revoked_at"].is_null());
    // No owner/subject leak
    assert!(v.get("name").is_none());
    assert!(v.get("user_id").is_none());

    // Revoke, then expect revoked
    let r = client.post(format!("/certificates/{}/revoke", cert.id)).dispatch().await;
    assert_eq!(r.status(), Status::Ok);
    let resp = client.get(format!("/certificates/validate?serial={serial}")).dispatch().await;
    let v: serde_json::Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(v["status"], "revoked");
    assert!(v["revoked_at"].is_number());

    Ok(())
}

#[tokio::test]
async fn validate_unknown_serial_is_unknown() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/validate?serial=deadbeef").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let v: serde_json::Value = serde_json::from_str(&resp.into_string().await.unwrap())?;
    assert_eq!(v["status"], "unknown");
    assert!(v["not_after"].is_null());

    Ok(())
}

#[tokio::test]
async fn validate_missing_serial_is_bad_request() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/validate?serial=").dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest);
    Ok(())
}

#[tokio::test]
async fn issuance_records_serial() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let cert = client.create_client_cert(None, Some("pw".to_string()), None).await?;

    // Download the issued cert and derive its serial
    let req = client.get(format!("/certificates/{}/download", cert.id));
    let resp = req.dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let p12 = resp.into_bytes().await.unwrap();
    let serial = serial_hex_from_p12(&p12, "pw");
    assert!(!serial.is_empty());

    Ok(())
}

#[tokio::test]
async fn ca_download_pem_default_and_der() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    // Default (PEM)
    let resp = client.get("/certificates/ca/download").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let cd = resp.headers().get_one("Content-Disposition").unwrap_or("").to_string();
    let body = resp.into_bytes().await.unwrap();
    assert!(body.starts_with(b"-----BEGIN CERTIFICATE-----"), "default must be PEM");
    assert!(cd.contains("ca.crt"), "filename should be ca.crt, got {cd}");

    // Explicit DER
    let resp = client.get("/certificates/ca/download?format=der").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let cd = resp.headers().get_one("Content-Disposition").unwrap_or("").to_string();
    let body = resp.into_bytes().await.unwrap();
    assert!(!body.starts_with(b"-----BEGIN"), "DER must not be PEM-armored");
    assert!(cd.contains("ca.der"), "filename should be ca.der, got {cd}");

    Ok(())
}

#[tokio::test]
async fn fullchain_internal_ca_is_single_pem() -> Result<()> {
    // The setup wizard creates a self-signed internal TLS CA with id 1.
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/ca/1/fullchain").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let body = resp.into_bytes().await.unwrap();
    let text = String::from_utf8_lossy(&body);
    // Self-signed internal CA → exactly one certificate in the chain.
    assert_eq!(text.matches("-----BEGIN CERTIFICATE-----").count(), 1);
    Ok(())
}

#[tokio::test]
async fn fullchain_unknown_ca_is_404() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/ca/9999/fullchain").dispatch().await;
    assert_eq!(resp.status(), Status::NotFound);
    Ok(())
}
