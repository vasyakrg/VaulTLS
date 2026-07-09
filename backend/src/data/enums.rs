use num_enum::TryFromPrimitive;
use rocket_okapi::JsonSchema;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ValueRef};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, TryFromPrimitive, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UserRole {
    User = 0,
    Admin = 1
}

impl FromSql for UserRole {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                UserRole::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum MailEncryption {
    #[default]
    None = 0,
    TLS = 1,
    STARTTLS = 2
}

impl From<String> for MailEncryption {
    fn from(value: String) -> Self {
        match value.to_uppercase().as_str()
        {
            "TLS" => MailEncryption::TLS,
            "STARTTLS" => MailEncryption::STARTTLS,
            _ => MailEncryption::None
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum PasswordRule {
    #[default]
    Optional = 0,
    Required = 1,
    System = 2
}

#[derive(Debug, Clone)]
pub enum CertData {
    Pkcs12(Vec<u8>),
    Pem(Vec<u8>),
    SshBundle(Vec<u8>),
}

impl CertData {
    pub fn into_bytes(self) -> Vec<u8> {
        match self { CertData::Pkcs12(b) | CertData::Pem(b) | CertData::SshBundle(b) => b }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self { CertData::Pkcs12(b) | CertData::Pem(b) | CertData::SshBundle(b) => b }
    }
}

impl Default for CertData {
    fn default() -> Self {
        CertData::Pkcs12(Vec::new())
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateType {
    #[default]
    TLSClient = 0,
    TLSServer = 1,
    SSHClient = 10,
    SSHServer = 11,
}

impl FromSql for CertificateType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CertificateType::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CAType {
    #[default]
    TLS = 0,
    SSH = 1
}

impl FromSql for CAType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CAType::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CertificateRenewMethod {
    #[default]
    None = 0,
    Notify = 1,
    Renew = 2,
    RenewAndNotify = 3
}

impl FromSql for CertificateRenewMethod {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Integer(i) => {
                let value = i as u8;
                CertificateRenewMethod::try_from(value)
                    .map_err(|_| FromSqlError::InvalidType)
            },
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, JsonSchema, TryFromPrimitive, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TimespanUnit {
    #[default]
    Year = 0,
    Month = 1,
    Day = 2,
    Hour = 3
}

#[derive(serde::Deserialize, rocket::form::FromFormField, rocket_okapi::JsonSchema, Clone, Debug, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DataFormat {
    #[default]
    DER,
    PEM,
}

impl From<String> for DataFormat {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "pem" => DataFormat::PEM,
            _ => DataFormat::DER,
        }
    }
}

#[derive(serde::Serialize, rocket_okapi::JsonSchema, Clone, Debug, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    Valid,
    Revoked,
    Expired,
    NotYetValid,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditActorType { User, Service, Anonymous }

impl AuditActorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditActorType::User => "user",
            AuditActorType::Service => "service",
            AuditActorType::Anonymous => "anonymous",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditResult { Success, Failure }

impl AuditResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditResult::Success => "success",
            AuditResult::Failure => "failure",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    Login, Logout, DownloadCertificate, FetchCertificatePassword,
    CreateCa, ImportCa, DeleteCa, RevokeCertificate, DeleteCertificate,
    CreateUser, UpdateUser, DeleteUser,
    CreateGroup, UpdateGroup, DeleteGroup,
    CreateServiceAccount, RevokeServiceAccount, DeleteServiceAccount,
    UpdateSettings,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Login => "login",
            AuditAction::Logout => "logout",
            AuditAction::DownloadCertificate => "download_certificate",
            AuditAction::FetchCertificatePassword => "fetch_certificate_password",
            AuditAction::CreateCa => "create_ca",
            AuditAction::ImportCa => "import_ca",
            AuditAction::DeleteCa => "delete_ca",
            AuditAction::RevokeCertificate => "revoke_certificate",
            AuditAction::DeleteCertificate => "delete_certificate",
            AuditAction::CreateUser => "create_user",
            AuditAction::UpdateUser => "update_user",
            AuditAction::DeleteUser => "delete_user",
            AuditAction::CreateGroup => "create_group",
            AuditAction::UpdateGroup => "update_group",
            AuditAction::DeleteGroup => "delete_group",
            AuditAction::CreateServiceAccount => "create_service_account",
            AuditAction::RevokeServiceAccount => "revoke_service_account",
            AuditAction::DeleteServiceAccount => "delete_service_account",
            AuditAction::UpdateSettings => "update_settings",
        }
    }
}

impl std::str::FromStr for AuditAction {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "login" => Ok(AuditAction::Login),
            "logout" => Ok(AuditAction::Logout),
            "download_certificate" => Ok(AuditAction::DownloadCertificate),
            "fetch_certificate_password" => Ok(AuditAction::FetchCertificatePassword),
            "create_ca" => Ok(AuditAction::CreateCa),
            "import_ca" => Ok(AuditAction::ImportCa),
            "delete_ca" => Ok(AuditAction::DeleteCa),
            "revoke_certificate" => Ok(AuditAction::RevokeCertificate),
            "delete_certificate" => Ok(AuditAction::DeleteCertificate),
            "create_user" => Ok(AuditAction::CreateUser),
            "update_user" => Ok(AuditAction::UpdateUser),
            "delete_user" => Ok(AuditAction::DeleteUser),
            "create_group" => Ok(AuditAction::CreateGroup),
            "update_group" => Ok(AuditAction::UpdateGroup),
            "delete_group" => Ok(AuditAction::DeleteGroup),
            "create_service_account" => Ok(AuditAction::CreateServiceAccount),
            "revoke_service_account" => Ok(AuditAction::RevokeServiceAccount),
            "delete_service_account" => Ok(AuditAction::DeleteServiceAccount),
            "update_settings" => Ok(AuditAction::UpdateSettings),
            _ => Err(()),
        }
    }
}