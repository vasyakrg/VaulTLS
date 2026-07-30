use anyhow::Result;
use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;
use passwords::PasswordGenerator;
use crate::certs::ssh_cert::extract_ssh_serial_number;
use crate::certs::tls_cert::{extract_pem_serial_number, extract_pkcs12_serial_number};
use crate::data::enums::{CAType, CertData, CertificateRenewMethod, CertificateType};
use crate::data::objects::Name;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
/// Certificate can be either SSH or TLS certificate.
pub struct Certificate {
    pub id: i64,
    pub name: Name,
    pub created_on: i64,
    pub valid_until: i64,
    pub certificate_type: CertificateType,
    pub user_id: i64,
    pub renew_method: CertificateRenewMethod,
    pub ca_id: Option<i64>,
    pub revoked_at: Option<i64>,
    pub acme_provider_id: Option<i64>,
    /// Номер текущей версии; растёт при каждой замене содержимого.
    #[serde(default = "default_version")]
    pub version: i64,
    /// SHA-256 от DER leaf-сертификата, hex. None у записей, не прошедших бэкфилл.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// True только у сертификатов, загруженных файлом — только их можно заменять.
    #[serde(default)]
    pub is_imported: bool,
    #[serde(skip)]
    pub data: CertData,
    #[serde(skip)]
    pub password: String
}

/// Одна запись в истории версий сертификата.
/// У текущей версии `version_id` = None: она хранится в `user_certificates`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CertificateVersionEntry {
    pub version: i64,
    pub version_id: Option<i64>,
    pub current: bool,
    pub created_on: i64,
    pub valid_until: i64,
    pub serial_hex: Option<String>,
    pub fingerprint: Option<String>,
    pub replaced_at: Option<i64>,
    pub replaced_by: Option<i64>,
}

fn default_version() -> i64 { 1 }

impl Certificate {
    pub(crate) fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        let raw: Vec<u8> = row.get(4)?;
        let certificate_type: CertificateType = row.get(7)?;
        let data = match certificate_type {
            CertificateType::SSHClient | CertificateType::SSHServer => CertData::SshBundle(raw),
            _ => if raw.starts_with(b"-----BEGIN CERTIFICATE-----") {
                CertData::Pem(raw)
            } else {
                CertData::Pkcs12(raw)
            },
        };
        Ok(Certificate {
            id: row.get(0)?,
            name: row.get(1)?,
            created_on: row.get(2)?,
            valid_until: row.get(3)?,
            data,
            password: row.get(5).unwrap_or_default(),
            user_id: row.get(6)?,
            certificate_type,
            renew_method: row.get(8)?,
            ca_id: row.get(9)?,
            revoked_at: row.get(10)?,
            acme_provider_id: row.get(11)?,
            version: row.get(12).unwrap_or(1),
            fingerprint: row.get(13).unwrap_or(None),
            is_imported: row.get::<_, i64>(14).unwrap_or(0) == 1,
        })
    }

    pub(crate) fn get_serial(&self) -> Result<Vec<u8>> {
        match self.data {
            CertData::Pkcs12(ref pkcs12) => { extract_pkcs12_serial_number(pkcs12, &self.password) }
            CertData::Pem(ref pem) => { extract_pem_serial_number(pem) }
            CertData::SshBundle(ref ssh) => { extract_ssh_serial_number(ssh, &self.name.to_string()) }
        }
    }

    /// SHA-256 от DER leaf-сертификата в нижнем регистре hex.
    pub(crate) fn get_fingerprint(&self) -> Result<String> {
        use crate::certs::import::{parse_cert, parse_pkcs12};
        let leaf = match &self.data {
            CertData::Pkcs12(der) => parse_pkcs12(der, &self.password)?.0,
            CertData::Pem(pem) => parse_cert(pem)?,
            CertData::SshBundle(_) => {
                return Err(anyhow::anyhow!("SSH certificates have no X.509 fingerprint"))
            }
        };
        let digest = leaf.digest(openssl::hash::MessageDigest::sha256())?;
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, Debug)]
pub struct CA {
    pub id: i64,
    pub name: Name,
    pub created_on: i64,
    pub valid_until: i64,
    pub ca_type: CAType,
    #[serde(skip)]
    pub cert: Vec<u8>,
    #[serde(rename = "has_private_key", serialize_with = "crate::helper::serialize_has_private_key", skip_deserializing)]
    pub key: Vec<u8>,
    #[serde(skip)]
    pub crl_number: i64,
    pub is_imported: bool,
}

impl CA {
    /// True if this CA holds a usable private key (i.e. can issue/revoke).
    pub fn has_private_key(&self) -> bool {
        !self.key.is_empty()
    }
}

/// Saves the CA certificate to a file for filesystem access.
#[cfg(not(feature = "test-mode"))]
pub(crate) fn save_ca(ca: &CA) -> anyhow::Result<()> {
    use std::fs;
    use crate::ApiError;
    use crate::certs::tls_cert::get_tls_pem;
    use crate::certs::ssh_cert::get_ssh_pem;
    use crate::constants::{CA_DIR_PATH, CA_FILE_PATTERN, CA_SSH_FILE_PATH, CA_TLS_FILE_PATH};
    let pem = match ca.ca_type {
        CAType::TLS => get_tls_pem(ca)?,
        CAType::SSH => get_ssh_pem(ca)?,
    };
    let ca_id_file_path = CA_FILE_PATTERN.replace("{}", &ca.id.to_string());
    fs::create_dir_all(CA_DIR_PATH)?;
    fs::write(ca_id_file_path, pem.clone()).map_err(|e| ApiError::Other(e.to_string()))?;
    match ca.ca_type {
        CAType::SSH => fs::write(CA_SSH_FILE_PATH, pem).map_err(|e| ApiError::Other(e.to_string()))?,
        CAType::TLS => fs::write(CA_TLS_FILE_PATH, pem).map_err(|e| ApiError::Other(e.to_string()))?,
    }
    Ok(())
}

#[cfg(feature = "test-mode")]
pub(crate) fn save_ca(_ca: &CA) -> anyhow::Result<()> {
    Ok(())
}

/// Returns the password for the certificate. If none provided returns empty string.
pub fn get_password(system_generated_password: bool, cert_password: &Option<String>) -> String {
    if system_generated_password {
        let pg = PasswordGenerator {
            length: 20,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            spaces: false,
            exclude_similar_characters: false,
            strict: true,
        };
        pg.generate_one().unwrap()
    } else {
        match cert_password {
            Some(p) => p.clone(),
            None => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::import::tests_support::self_signed_ca;

    #[test]
    fn fingerprint_is_stable_lowercase_sha256_hex() {
        let (cert, _key) = self_signed_ca("fingerprint-test");
        let pem = cert.to_pem().unwrap();
        let c = Certificate {
            id: 1,
            name: crate::data::objects::Name::from("fingerprint-test".to_string()),
            created_on: 0,
            valid_until: 0,
            certificate_type: crate::data::enums::CertificateType::TLSServer,
            user_id: 1,
            renew_method: crate::data::enums::CertificateRenewMethod::None,
            ca_id: None,
            revoked_at: None,
            acme_provider_id: None,
            data: crate::data::enums::CertData::Pem(pem),
            password: String::new(),
            version: 1,
            fingerprint: None,
            is_imported: true,
        };

        let fp = c.get_fingerprint().unwrap();
        assert_eq!(fp.len(), 64, "sha256 hex — 64 символа");
        assert_eq!(fp, fp.to_lowercase());
        assert!(fp.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(fp, c.get_fingerprint().unwrap(), "отпечаток детерминирован");
    }

    #[test]
    fn fingerprint_of_ssh_bundle_is_an_error() {
        let c = Certificate {
            id: 1,
            name: crate::data::objects::Name::from("ssh".to_string()),
            created_on: 0,
            valid_until: 0,
            certificate_type: crate::data::enums::CertificateType::SSHServer,
            user_id: 1,
            renew_method: crate::data::enums::CertificateRenewMethod::None,
            ca_id: None,
            revoked_at: None,
            acme_provider_id: None,
            data: crate::data::enums::CertData::SshBundle(vec![1, 2, 3]),
            password: String::new(),
            version: 1,
            fingerprint: None,
            is_imported: false,
        };
        assert!(c.get_fingerprint().is_err());
    }
}