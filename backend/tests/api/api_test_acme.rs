//! Интеграционные тесты ACME-протокола: регистрация аккаунта с EAB,
//! повторная регистрация тем же/чужим ключом (RFC 8555 §7.3.1/§7.3.4)
//! и создание заказа подписанным JWS.
//!
//! Тестовый рокет использует `Settings::default()` — `vaultls_url` пуст,
//! поэтому все URL в JWS/kid строятся от пустой базы ("/api/acme/...").

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey};

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use rocket::http::{ContentType, Status};
use serde_json::{json, Value};

use crate::common::test_client::VaulTLSClient;
use anyhow::Result;

const ACME_BASE: &str = "/api/acme";

/// Свежая нонса из ответа new-nonce.
async fn fresh_nonce(client: &VaulTLSClient) -> String {
    let resp = client.get(format!("{ACME_BASE}/new-nonce")).dispatch().await;
    assert_eq!(resp.status(), Status::NoContent, "new-nonce failed");
    resp.headers()
        .get_one("Replay-Nonce")
        .expect("Replay-Nonce header present")
        .to_string()
}

/// Только что сгенерированный P-256 ключ + его JWK.
struct AcmeKey {
    ec: EcKey<Private>,
    jwk: Value,
}

fn gen_key() -> AcmeKey {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut x = openssl::bn::BigNum::new().unwrap();
    let mut y = openssl::bn::BigNum::new().unwrap();
    ec.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
        .unwrap();
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": B64.encode(padded32(x.to_vec())),
        "y": B64.encode(padded32(y.to_vec())),
    });
    AcmeKey { ec, jwk }
}

fn padded32(mut bytes: Vec<u8>) -> Vec<u8> {
    assert!(bytes.len() <= 32);
    let mut out = vec![0u8; 32];
    out.append(&mut bytes); // BigNum::to_vec уже big-endian со старших байт
    out
}

/// ES256-подпись в JOSE-формате (raw r||s, 64 байта).
fn es256_sign(ec: &EcKey<Private>, data: &[u8]) -> Vec<u8> {
    let pkey = PKey::from_ec_key(ec.clone()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(data).unwrap();
    let der = signer.sign_to_vec().unwrap();
    let sig = openssl::ecdsa::EcdsaSig::from_der(&der).unwrap();
    let mut raw = padded32(sig.r().to_vec());
    raw.extend(padded32(sig.s().to_vec()));
    raw
}

/// ExternalAccountBinding: HS256-подпись над "{protected}.{payload}",
/// где payload — JWK аккаунтного ключа.
fn eab_binding(jwk: &Value, eab_kid: &str, eab_hmac_b64: &str, url: &str) -> Value {
    let hmac_key = B64.decode(eab_hmac_b64).unwrap();
    let eab_protected = json!({"alg": "HS256", "kid": eab_kid, "url": url});
    let eab_protected_b64 = B64.encode(eab_protected.to_string().as_bytes());
    let eab_payload_b64 = B64.encode(jwk.to_string().as_bytes());
    let hmac = PKey::hmac(&hmac_key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &hmac).unwrap();
    signer
        .update(format!("{eab_protected_b64}.{eab_payload_b64}").as_bytes())
        .unwrap();
    let mac = signer.sign_to_vec().unwrap();
    json!({
        "protected": eab_protected_b64,
        "payload": eab_payload_b64,
        "signature": B64.encode(mac),
    })
}

/// new-account JWS: подписан самим аккаунтным ключом (jwk в заголовке, kid запрещён).
fn new_account_jws(key: &AcmeKey, nonce: &str, eab_kid: &str, eab_hmac_b64: &str) -> String {
    let url = format!("{ACME_BASE}/new-account");
    let protected = json!({"alg": "ES256", "jwk": key.jwk, "nonce": nonce, "url": url});
    let protected_b64 = B64.encode(protected.to_string().as_bytes());
    let payload = json!({
        "termsOfServiceAgreed": true,
        "externalAccountBinding": eab_binding(&key.jwk, eab_kid, eab_hmac_b64, &url),
    });
    let payload_b64 = B64.encode(payload.to_string().as_bytes());
    let sig = es256_sign(&key.ec, format!("{protected_b64}.{payload_b64}").as_bytes());
    json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": B64.encode(sig),
    })
    .to_string()
}

/// new-order JWS: kid вместо jwk.
fn new_order_jws(key: &AcmeKey, kid: &str, nonce: &str, identifiers: Value) -> String {
    let protected = json!({
        "alg": "ES256",
        "kid": kid,
        "nonce": nonce,
        "url": format!("{ACME_BASE}/new-order"),
    });
    let protected_b64 = B64.encode(protected.to_string().as_bytes());
    let payload = json!({ "identifiers": identifiers });
    let payload_b64 = B64.encode(payload.to_string().as_bytes());
    let sig = es256_sign(&key.ec, format!("{protected_b64}.{payload_b64}").as_bytes());
    json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": B64.encode(sig),
    })
    .to_string()
}

async fn create_eab_account(client: &VaulTLSClient, domains: &[&str]) -> (i64, String, String) {
    let body = json!({
        "name": "probe",
        "allowed_domains": domains,
        "ca_id": 1,
        "auto_validate": true,
    });
    let resp = client.post("/acme/accounts")
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch().await;
    let status = resp.status();
    let text = resp.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "create ACME account failed: {status} {text}");
    let created: Value = serde_json::from_str(&text).unwrap();
    (
        created["id"].as_i64().unwrap(),
        created["eab_kid"].as_str().unwrap().to_string(),
        created["eab_hmac_key"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn acme_account_reuse_same_key_returns_200_and_order_signs() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (_id, eab_kid, eab_hmac) = create_eab_account(&client, &["*.haproxy-viz.internal"]).await;

    // Первая регистрация: ключ K1 → 201 + Location
    let key = gen_key();
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-account"))
        .header(ContentType::JSON)
        .body(new_account_jws(&key, &nonce, &eab_kid, &eab_hmac))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Created, "first new-account failed");
    let kid = resp.headers().get_one("Location").expect("Location header").to_string();
    assert!(kid.starts_with(&format!("{ACME_BASE}/account/")), "kid: {kid}");

    // Повторная регистрация ТЕМ ЖЕ ключом → 200 с тем же kid (RFC 8555 §7.3.1)
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-account"))
        .header(ContentType::JSON)
        .body(new_account_jws(&key, &nonce, &eab_kid, &eab_hmac))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "same-key re-registration must be 200");
    assert_eq!(resp.headers().get_one("Location"), Some(kid.as_str()), "same kid");

    // new-order подписан тем же ключом → заказ создаётся
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-order"))
        .header(ContentType::JSON)
        .body(new_order_jws(
            &key,
            &kid,
            &nonce,
            json!([{"type": "dns", "value": "probe-01.haproxy-viz.internal"}]),
        ))
        .dispatch().await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Created, "new-order failed: {status} {body}");
    let order: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(order["status"], "pending");
    Ok(())
}

#[tokio::test]
async fn acme_account_reuse_other_key_is_rejected() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (_id, eab_kid, eab_hmac) = create_eab_account(&client, &["*.haproxy-viz.internal"]).await;

    // Регистрируем аккаунт ключом K1
    let key1 = gen_key();
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-account"))
        .header(ContentType::JSON)
        .body(new_account_jws(&key1, &nonce, &eab_kid, &eab_hmac))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Created);
    let kid = resp.headers().get_one("Location").expect("Location header").to_string();

    // Та же EAB-пара с НОВЫМ ключом K2 → отказ на регистрации, а не
    // молчаливый возврат kid аккаунта с ключом K1
    let key2 = gen_key();
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-account"))
        .header(ContentType::JSON)
        .body(new_account_jws(&key2, &nonce, &eab_kid, &eab_hmac))
        .dispatch().await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Forbidden, "got: {status} body={body}");
    let err: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(err["type"], "urn:ietf:params:acme:error:unauthorized", "{body}");
    assert!(
        err["detail"].as_str().unwrap().contains("different account key"),
        "expected clear EAB-rebind error, got: {body}"
    );

    // И заказ ключом K2 под kid K1 теперь тоже явно не пройдёт молча:
    // прежнее поведение возвращало 400 "Signature verification failed" —
    // проверяем, что подпись K1 продолжает работать (K1 не подменён K2)
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-order"))
        .header(ContentType::JSON)
        .body(new_order_jws(
            &key1,
            &kid,
            &nonce,
            json!([{"type": "dns", "value": "probe-02.haproxy-viz.internal"}]),
        ))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Created, "K1 order must still work");
    Ok(())
}

#[tokio::test]
async fn acme_order_wildcard_single_level_enforced() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (_id, eab_kid, eab_hmac) = create_eab_account(&client, &["*.haproxy-viz.internal"]).await;

    let key = gen_key();
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-account"))
        .header(ContentType::JSON)
        .body(new_account_jws(&key, &nonce, &eab_kid, &eab_hmac))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Created);
    let kid = resp.headers().get_one("Location").expect("Location header").to_string();

    // `*.haproxy-viz.internal` матчит ровно один лейбл:
    // probe-01.test.haproxy-viz.internal НЕ разрешён
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-order"))
        .header(ContentType::JSON)
        .body(new_order_jws(
            &key,
            &kid,
            &nonce,
            json!([{"type": "dns", "value": "probe-01.test.haproxy-viz.internal"}]),
        ))
        .dispatch().await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Forbidden, "got: {status} body={body}");
    let err: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(err["type"], "urn:ietf:params:acme:error:rejectedIdentifier", "{body}");
    Ok(())
}

/// JWS с kid (без jwk в заголовке) для произвольного ACME-URL и payload.
fn kid_jws(key: &AcmeKey, kid: &str, nonce: &str, url: &str, payload: Value) -> String {
    let protected = json!({"alg": "ES256", "kid": kid, "nonce": nonce, "url": url});
    let protected_b64 = B64.encode(protected.to_string().as_bytes());
    let payload_b64 = B64.encode(payload.to_string().as_bytes());
    let sig = es256_sign(&key.ec, format!("{protected_b64}.{payload_b64}").as_bytes());
    json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": B64.encode(sig),
    })
    .to_string()
}

/// RSA-ключ + самоподписанный CSR (DER) на домен.
fn gen_csr(domain: &str) -> Vec<u8> {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509ReqBuilder};
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", domain).unwrap();
    let mut req = X509ReqBuilder::new().unwrap();
    req.set_subject_name(&name.build()).unwrap();
    req.set_pubkey(&pkey).unwrap();
    req.sign(&pkey, MessageDigest::sha256()).unwrap();
    req.build().to_der().unwrap()
}

/// Полный путь до валидного заказа: регистрация → new-order → challenge
/// (auto_validate) → finalize с CSR. Возвращает (order_id, certificate_id).
async fn issue_through_acme(client: &VaulTLSClient, key: &AcmeKey, kid: &str, domain: &str) -> (i64, i64) {
    // new-order
    let nonce = fresh_nonce(client).await;
    let resp = client.post(format!("{ACME_BASE}/new-order"))
        .header(ContentType::JSON)
        .body(kid_jws(key, kid, &nonce, &format!("{ACME_BASE}/new-order"),
            json!({"identifiers": [{"type": "dns", "value": domain}]})))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Created, "new-order failed");
    let order: Value = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    // id заказа берём из authz URL: {base}/api/acme/authz/{order_id}-0
    let authz_url = order["authorizations"].as_array().unwrap()[0].as_str().unwrap().to_string();
    let order_id: i64 = authz_url.rsplit('/').next().unwrap().split('-').next().unwrap().parse().unwrap();

    // challenge http-01 → auto_validate сразу валидирует
    let nonce = fresh_nonce(client).await;
    let resp = client.post(format!("{ACME_BASE}/chall/{order_id}/http-01/0"))
        .header(ContentType::JSON)
        .body(kid_jws(key, kid, &nonce, &format!("{ACME_BASE}/chall/{order_id}/http-01/0"), json!({})))
        .dispatch().await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "challenge failed: {status} {body}");

    // finalize с CSR
    let nonce = fresh_nonce(client).await;
    let resp = client.post(format!("{ACME_BASE}/order/{order_id}/finalize"))
        .header(ContentType::JSON)
        .body(kid_jws(key, kid, &nonce, &format!("{ACME_BASE}/order/{order_id}/finalize"),
            json!({"csr": B64.encode(gen_csr(domain))})))
        .dispatch().await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "finalize failed: {status} {body}");

    // certificate_id из админского списка заказов
    let resp = client.get("/acme/orders").dispatch().await;
    let orders: Vec<Value> = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    let order = orders.iter().find(|o| o["id"].as_i64() == Some(order_id)).expect("order in admin list");
    (order_id, order["certificate_id"].as_i64().expect("order has certificate"))
}

#[tokio::test]
async fn acme_purge_requires_deactivated_and_cascades_orders() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (account_id, eab_kid, eab_hmac) = create_eab_account(&client, &["*.haproxy-viz.internal"]).await;

    // Регистрируем аккаунт ключом и создаём заказ
    let key = gen_key();
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-account"))
        .header(ContentType::JSON)
        .body(new_account_jws(&key, &nonce, &eab_kid, &eab_hmac))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Created);
    let kid = resp.headers().get_one("Location").expect("Location header").to_string();

    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-order"))
        .header(ContentType::JSON)
        .body(kid_jws(&key, &kid, &nonce, &format!("{ACME_BASE}/new-order"),
            json!({"identifiers": [{"type": "dns", "value": "purge.haproxy-viz.internal"}]})))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Created, "new-order failed");

    // Purge АКТИВНОГО аккаунта запрещён
    let resp = client.delete(format!("/acme/accounts/{account_id}/purge")).dispatch().await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::BadRequest, "got: {status} body={body}");

    // Деактивация (существующий DELETE) → purge разрешён
    let resp = client.delete(format!("/acme/accounts/{account_id}")).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let resp = client.delete(format!("/acme/accounts/{account_id}/purge")).dispatch().await;
    assert_eq!(resp.status(), Status::Ok, "purge of deactivated account failed");

    // Аккаунт и его заказы удалены полностью
    let resp = client.get("/acme/accounts").dispatch().await;
    let accounts: Vec<Value> = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert!(accounts.iter().all(|a| a["id"].as_i64() != Some(account_id)), "account must be gone");
    let resp = client.get("/acme/orders").dispatch().await;
    let orders: Vec<Value> = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert!(orders.is_empty(), "orders must cascade-delete with the account");
    Ok(())
}

#[tokio::test]
async fn acme_order_revoke_and_delete() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let (_account_id, eab_kid, eab_hmac) = create_eab_account(&client, &["*.haproxy-viz.internal"]).await;

    let key = gen_key();
    let nonce = fresh_nonce(&client).await;
    let resp = client.post(format!("{ACME_BASE}/new-account"))
        .header(ContentType::JSON)
        .body(new_account_jws(&key, &nonce, &eab_kid, &eab_hmac))
        .dispatch().await;
    assert_eq!(resp.status(), Status::Created);
    let kid = resp.headers().get_one("Location").expect("Location header").to_string();

    let (order_id, cert_id) = issue_through_acme(&client, &key, &kid, "revoke.haproxy-viz.internal").await;

    // Отзыв сертификата заказа → серт помечен отозванным
    let resp = client.post(format!("/acme/orders/{order_id}/revoke")).dispatch().await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "revoke failed: {status} {body}");

    let resp = client.get("/certificates").dispatch().await;
    let certs: Vec<Value> = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    let cert = certs.iter().find(|c| c["id"].as_i64() == Some(cert_id)).expect("cert in list");
    assert!(!cert["revoked_at"].is_null(), "certificate must be revoked");

    // Повторный отзыв → 400 (уже отозван)
    let resp = client.post(format!("/acme/orders/{order_id}/revoke")).dispatch().await;
    assert_eq!(resp.status(), Status::BadRequest);

    // Удаление заказа → заказ исчезает, сертификат остаётся
    let resp = client.delete(format!("/acme/orders/{order_id}")).dispatch().await;
    assert_eq!(resp.status(), Status::Ok);
    let resp = client.get("/acme/orders").dispatch().await;
    let orders: Vec<Value> = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert!(orders.iter().all(|o| o["id"].as_i64() != Some(order_id)), "order must be gone");
    let resp = client.get("/certificates").dispatch().await;
    let certs: Vec<Value> = serde_json::from_str(&resp.into_string().await.unwrap()).unwrap();
    assert!(certs.iter().any(|c| c["id"].as_i64() == Some(cert_id)), "certificate must survive order deletion");
    Ok(())
}
