use std::io::{Cursor, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use anyhow::Result;
use ssh_key::{Certificate, PrivateKey};
use zip::ZipArchive;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Builder, X509NameBuilder};
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier};

pub(crate) fn get_timestamp_ms(from_now_in_years: u64) -> i64 {
    let time = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * from_now_in_years);
    time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

pub(crate) fn get_timestamp_s(from_now_in_years: u64) -> i64 {
    let time = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * from_now_in_years);
    time.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

pub fn extract_ssh_cert_key_bundle(zip_data: &[u8]) -> Result<(Certificate, PrivateKey)> {
    let cursor = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(cursor)?;

    let mut cert_bytes = Vec::new();
    let mut key_bytes = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let file_name = file.name().to_string();

        if file_name.ends_with(".pub") {
            file.read_to_end(&mut cert_bytes)?;
        } else if file_name.ends_with(".key") {
            file.read_to_end(&mut key_bytes)?;
        }
    }

    let cert_str = String::from_utf8(cert_bytes.clone())?;
    let cert = ssh_key::Certificate::from_openssh(&cert_str)?;

    let key_str = String::from_utf8(key_bytes.clone())?;
    let key = ssh_key::PrivateKey::from_openssh(&key_str)?;

    Ok((cert, key))
}

/// Generate a self-signed CA cert+key PEM pair with given CN.
pub(crate) fn self_signed_ca_pem(cn: &str) -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let key = PKey::from_ec_key(ec_key).unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", cn).unwrap();
    let name = name_builder.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None)).unwrap();
    builder.append_extension(ski).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let cert_pem = cert.to_pem().unwrap();
    let key_pem = key.private_key_to_pem_pkcs8().unwrap();
    (cert_pem, key_pem)
}

/// Generate a leaf cert signed by `ca_pem`/`ca_key_pem` with given CN.
/// Returns (leaf_pem, leaf_key_pem).
pub(crate) fn leaf_signed_by_pem(cn: &str, ca_pem: &[u8], ca_key_pem: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let ca = openssl::x509::X509::from_pem(ca_pem).unwrap();
    let ca_key = PKey::private_key_from_pem(ca_key_pem).unwrap();

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let leaf_key = PKey::from_ec_key(ec_key).unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", cn).unwrap();
    let name = name_builder.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca.subject_name()).unwrap();
    builder.set_pubkey(&leaf_key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(90).unwrap()).unwrap();
    // SKI for the leaf
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(&ca), None)).unwrap();
    builder.append_extension(ski).unwrap();
    // AKI referencing CA
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(Some(&ca), None))
        .unwrap();
    builder.append_extension(aki).unwrap();
    builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let leaf_cert = builder.build();

    let leaf_pem = leaf_cert.to_pem().unwrap();
    let leaf_key_pem = leaf_key.private_key_to_pem_pkcs8().unwrap();
    (leaf_pem, leaf_key_pem)
}

/// Build a multipart body for POST /certificates/import
/// Fields: cert (file), key (file), chain (file), user_id (text)
pub(crate) fn multipart_import_leaf(
    boundary: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
    chain_pem: &[u8],
    user_id: i64,
) -> Vec<u8> {
    let mut body = Vec::new();

    // cert
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"cert\"; filename=\"leaf.pem\"\r\n");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(cert_pem);
    body.extend_from_slice(b"\r\n");

    // key
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"key\"; filename=\"leaf.key\"\r\n");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(key_pem);
    body.extend_from_slice(b"\r\n");

    // chain
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"chain\"; filename=\"chain.pem\"\r\n");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(chain_pem);
    body.extend_from_slice(b"\r\n");

    // user_id (text field)
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"user_id\"\r\n");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(user_id.to_string().as_bytes());
    body.extend_from_slice(b"\r\n");

    // closing
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

/// Build a valid multipart/form-data body with two file fields.
pub(crate) fn multipart_two_files(
    boundary: &str,
    name1: &str, filename1: &str, data1: &[u8],
    name2: &str, filename2: &str, data2: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    // Part 1
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n", name1, filename1).as_bytes()
    );
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(data1);
    body.extend_from_slice(b"\r\n");
    // Part 2
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n", name2, filename2).as_bytes()
    );
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(data2);
    body.extend_from_slice(b"\r\n");
    // Closing boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}