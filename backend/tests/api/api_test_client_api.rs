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
