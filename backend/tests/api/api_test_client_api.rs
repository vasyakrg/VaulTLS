use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use openssl::pkcs12::Pkcs12;
use rocket::http::{Header, Status};

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

#[tokio::test]
async fn scalar_docs_served() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    let resp = client.get("/api/").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let html = resp.into_string().await.unwrap();
    assert!(html.contains("/api/openapi.json"), "HTML must reference the spec URL");
    assert!(html.contains("/api/scalar.js"), "HTML must reference the self-hosted bundle");

    let resp = client.get("/api/scalar.js").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    // Spec still served
    let resp = client.get("/api/openapi.json").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    Ok(())
}

#[tokio::test]
async fn ca_list_is_public_metadata_only() -> Result<()> {
    // new_setup creates a default CA but does NOT log in.
    let client = VaulTLSClient::new_setup().await;

    let resp = client.get("/certificates/ca").dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "CA list must be public");
    let body = resp.into_string().await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&body)?;

    assert!(v.is_array());
    assert!(!v.as_array().unwrap().is_empty(), "setup creates at least one CA");
    // Metadata is present...
    assert!(v[0].get("id").is_some());
    assert!(v[0].get("name").is_some());
    // ...but private key material / DER bytes are never serialized.
    assert!(!body.contains("\"key\""), "private key must not be serialized");
    assert!(!body.contains("BEGIN"), "no PEM/DER cert bytes in the list");

    Ok(())
}

#[tokio::test]
async fn download_unknown_ca_is_404() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/ca/9999/download").dispatch().await;
    assert_eq!(resp.status(), Status::NotFound, "unknown CA id must be 404, not 500");
    Ok(())
}

#[tokio::test]
async fn ca_bundle_is_public_and_empty_without_imported_cas() -> Result<()> {
    // new_setup creates a default (generated, not imported) CA and does NOT
    // log in, so the request carries no credentials at all.
    let client = VaulTLSClient::new_setup().await;
    let resp = client.get("/certificates/ca/bundle").dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "bundle must be public, and an empty trust pool is a valid body — not a 404");
    assert_eq!(
        resp.headers().get_one("Content-Type").unwrap_or(""),
        "application/x-pem-file"
    );
    assert!(resp.headers().get_one("ETag").is_some(), "empty bundle still carries validators");
    assert!(resp.headers().get_one("Last-Modified").is_some());
    let body = resp.into_bytes().await.unwrap();
    assert!(body.is_empty(), "setup created no imported CA, bundle must be empty");
    Ok(())
}

#[tokio::test]
async fn ca_bundle_contains_only_imported_tls_cas_in_id_order() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    // Generated CAs: the setup default (id 1) and an explicit second one.
    client.create_second_ca().await?;
    // Imported CAs, in creation (id) order.
    client.import_ca("Imported CA One").await?;
    client.import_ca("Imported CA Two").await?;

    let resp = client.get("/certificates/ca/bundle").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let text = String::from_utf8_lossy(&resp.into_bytes().await.unwrap()).to_string();
    let blocks: Vec<&str> = text.split("-----END CERTIFICATE-----").collect();
    assert_eq!(blocks.len(), 3, "2 certificates plus trailing whitespace, got {text}");
    let subjects: Vec<String> = blocks[..2]
        .iter()
        .map(|chunk| {
            let pem = format!("{chunk}-----END CERTIFICATE-----\n");
            let cert = openssl::x509::X509::from_pem(pem.as_bytes()).expect("bundle block must parse");
            cert.subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .map(|e| e.data().as_utf8().unwrap().to_string())
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(
        subjects,
        vec!["Imported CA One".to_string(), "Imported CA Two".to_string()],
        "bundle must contain exactly the imported CAs in id order — never the generated ones"
    );
    Ok(())
}

/// Last-Modified must track the set's own change time, not the certificates'
/// notBefore: deleting an imported CA has to advance it, so an
/// If-Modified-Since from before the deletion gets a full 200 — never a stale
/// 304 with the retired set.
#[tokio::test]
async fn ca_bundle_last_modified_tracks_set_changes() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.import_ca("Removable CA").await?;

    let resp = client.get("/certificates/ca/bundle").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let etag_before = resp.headers().get_one("ETag").unwrap().to_string();
    let lm_before = resp.headers().get_one("Last-Modified").unwrap().to_string();
    assert!(!resp.into_bytes().await.unwrap().is_empty());

    let cas: serde_json::Value = serde_json::from_str(
        &client.get("/certificates/ca").dispatch().await.into_string().await.unwrap(),
    )?;
    let id = cas
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["is_imported"].as_bool().unwrap_or(false))
        .and_then(|c| c["id"].as_i64())
        .expect("imported CA id");

    // The DB stamp has 1-second granularity: cross into a new second so the
    // deletion cannot land on the same value as the import.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let resp = client.delete(format!("/certificates/ca/{id}")).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);

    let resp = client.get("/certificates/ca/bundle").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    assert!(resp.into_bytes().await.unwrap_or_default().is_empty(), "set is empty again");

    // If-Modified-Since cached BEFORE the deletion must be a 200: the set
    // changed since. (A 304 here is exactly the stale-cache regression.)
    let resp = client.get("/certificates/ca/bundle").header(Header::new("If-Modified-Since", lm_before)).dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "deleting the last imported CA must invalidate If-Modified-Since caches");

    // Same for the old ETag; the new one still 304s.
    let resp = client.get("/certificates/ca/bundle").header(Header::new("If-None-Match", etag_before.clone())).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let resp = client.get("/certificates/ca/bundle").dispatch().await;
    let etag_after = resp.headers().get_one("ETag").unwrap().to_string();
    drop(resp.into_bytes());
    assert_ne!(etag_after, etag_before);
    let resp = client.get("/certificates/ca/bundle").header(Header::new("If-None-Match", etag_after)).dispatch().await;
    assert_eq!(resp.status(), Status::NotModified);
    Ok(())
}

#[tokio::test]
async fn ca_bundle_conditional_requests() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.import_ca("Conditional CA").await?;

    let resp = client.get("/certificates/ca/bundle").dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let etag = resp.headers().get_one("ETag").expect("ETag on 200").to_string();
    let last_modified = resp.headers().get_one("Last-Modified").expect("Last-Modified on 200").to_string();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "ETag must be a quoted strong tag, got {etag}");
    assert!(last_modified.ends_with(" GMT"), "Last-Modified must be an HTTP-date, got {last_modified}");
    drop(resp.into_bytes());

    // Matching If-None-Match → 304 with the same validators and no body.
    let resp = client.get("/certificates/ca/bundle").header(Header::new("If-None-Match", etag.clone())).dispatch().await;
    assert_eq!(resp.status(), Status::NotModified);
    assert_eq!(resp.headers().get_one("ETag"), Some(etag.as_str()));
    // A 304 carries no body: into_bytes is None when the response has none at all.
    assert!(resp.into_bytes().await.unwrap_or_default().is_empty());

    // Matching If-Modified-Since → 304 (checked only when If-None-Match is absent).
    let resp = client.get("/certificates/ca/bundle").header(Header::new("If-Modified-Since", last_modified.clone())).dispatch().await;
    assert_eq!(resp.status(), Status::NotModified);

    // Older If-Modified-Since → full body.
    let resp = client.get("/certificates/ca/bundle").header(Header::new("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT")).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    assert!(!resp.into_bytes().await.unwrap().is_empty());

    // Stale ETag → full body; the tag must change once the set changes.
    let resp = client.get("/certificates/ca/bundle").header(Header::new("If-None-Match", "\"stale\"".to_string())).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let new_etag = resp.headers().get_one("ETag").unwrap().to_string();
    drop(resp.into_bytes());
    client.import_ca("Conditional CA Two").await?;
    let resp = client.get("/certificates/ca/bundle").header(Header::new("If-None-Match", new_etag.clone())).dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "importing another CA must change the ETag");
    Ok(())
}
