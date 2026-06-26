use std::io::Cursor;
use rocket::{FromForm, Request, Response};
use rocket::http::{ContentType, Header, Status};
use rocket::response::Responder;
use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::okapi::schemars;
use rocket_okapi::{okapi, JsonSchema, OpenApiError};
use rocket_okapi::okapi::openapi3::{Responses, Response as OAResponse, MediaType, RefOr};
use rocket_okapi::response::OpenApiResponderInner;
use crate::data::enums::{CAType, CertificateRenewMethod, CertificateType, CertStatus, TimespanUnit, UserRole};
use crate::data::objects::Name;

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct IsSetupResponse {
    pub setup: bool,
    pub password: bool,
    pub oidc: String,
    pub default_language: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SetupRequest {
    pub name: String,
    pub email: String,
    pub ca_name: String,
    pub validity_duration: Option<u64>,
    pub validity_unit: Option<TimespanUnit>,
    pub password: Option<String>,
    pub default_language: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ChangePasswordRequest {
    pub old_password: Option<String>,
    pub new_password: String,
}

#[derive(FromForm, JsonSchema)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateCARequest {
    pub ca_name: Name,
    pub ca_type: CAType,
    pub validity_duration: Option<u64>,
    pub validity_unit: Option<TimespanUnit>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct CreateUserCertificateRequest {
    pub cert_name: Name,
    pub validity_duration: Option<u64>,
    pub validity_unit: Option<TimespanUnit>,
    pub user_id: i64,
    pub notify_user: Option<bool>,
    pub system_generated_password: bool,
    pub cert_password: Option<String>,
    pub cert_type: Option<CertificateType>,
    pub usage_limit: Option<Vec<String>>,
    pub renew_method: Option<CertificateRenewMethod>,
    pub ca_id: Option<i64>
}

#[derive(Serialize, Debug)]
pub struct DownloadResponse {
    pub content: Vec<u8>,
    pub filename: String,
    #[serde(skip)]
    pub content_type: ContentType,
}

impl DownloadResponse {
    /// Backwards-compatible constructor; defaults to text/plain.
    pub fn new(content: Vec<u8>, filename: &str) -> Self {
        Self { content, filename: filename.to_string(), content_type: ContentType::Text }
    }

    /// Constructor with an explicit content type.
    pub fn new_typed(content: Vec<u8>, filename: &str, content_type: ContentType) -> Self {
        Self { content, filename: filename.to_string(), content_type }
    }
}

impl<'r> Responder<'r, 'static> for DownloadResponse {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .status(Status::Ok)
            .header(self.content_type)
            .header(Header::new(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", self.filename),
            ))
            .sized_body(self.content.len(), Cursor::new(self.content))
            .ok()
    }
}

impl OpenApiResponderInner for DownloadResponse {
    fn responses(_gen: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        let mut responses = Responses::default();

        responses.responses.insert(
            "200".to_string(),
            RefOr::Object(OAResponse {
                description: "Downloadable binary file".to_string(),
                content: {
                    let mut content = okapi::Map::new();
                    content.insert(
                        "application/octet-stream".to_string(),
                        MediaType {
                            schema: None, // No schema needed for binary
                            ..Default::default()
                        },
                    );
                    content
                },
                ..Default::default()
            }),
        );

        Ok(responses)
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateUserRequest {
    pub user_name: String,
    pub user_email: String,
    pub password: Option<String>,
    pub role: UserRole
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ServiceTokenRequest {
    pub client_id: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ServiceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scopes: Vec<String>,
}

/// Pure status decision. Order matters: revocation first, then validity window.
pub fn compute_cert_status(
    now_ms: i64,
    created_on: i64,
    valid_until: i64,
    revoked_at: Option<i64>,
) -> CertStatus {
    if revoked_at.is_some() {
        CertStatus::Revoked
    } else if now_ms > valid_until {
        CertStatus::Expired
    } else if now_ms < created_on {
        CertStatus::NotYetValid
    } else {
        CertStatus::Valid
    }
}

#[derive(serde::Serialize, rocket_okapi::JsonSchema)]
pub struct CertStatusResponse {
    pub serial: String,
    pub status: CertStatus,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub revoked_at: Option<i64>,
    pub ca_id: Option<i64>,
}

#[cfg(test)]
mod cert_status_tests {
    use super::compute_cert_status;
    use crate::data::enums::CertStatus;

    #[test]
    fn valid_when_within_window_and_not_revoked() {
        // now between created_on and valid_until, not revoked
        assert_eq!(compute_cert_status(150, 100, 200, None), CertStatus::Valid);
    }

    #[test]
    fn revoked_takes_precedence_over_window() {
        // revoked_at set, even though now is within the validity window
        assert_eq!(compute_cert_status(150, 100, 200, Some(140)), CertStatus::Revoked);
    }

    #[test]
    fn expired_when_now_past_valid_until() {
        assert_eq!(compute_cert_status(250, 100, 200, None), CertStatus::Expired);
    }

    #[test]
    fn not_yet_valid_when_now_before_created_on() {
        assert_eq!(compute_cert_status(50, 100, 200, None), CertStatus::NotYetValid);
    }
}
