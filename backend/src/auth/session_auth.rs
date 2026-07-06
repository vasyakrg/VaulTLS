use std::collections::HashSet;
use crate::ApiError;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use const_format::concatcp;
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::{Object, SecurityRequirement, SecurityScheme, SecuritySchemeData};
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use uuid::Uuid;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use crate::data::enums::UserRole;
use crate::data::objects::AppState;

macro_rules! impl_openapi_auth {
    ($guard:ty, $role:literal) => {
        /// Generate OpenAPI documentation fora authentication guard
        impl<'r> OpenApiFromRequest<'r> for $guard {
            fn from_request_input(
                _gen: &mut OpenApiGenerator,
                _name: String,
                _required: bool,
            ) -> rocket_okapi::Result<RequestHeaderInput> {
                let security_scheme = SecurityScheme {
                    description: Some(
                        concatcp!("Use secure auth_token set by server to authenticate. Requires user role ", $role).to_owned(),
                    ),
                    data: SecuritySchemeData::ApiKey {
                        name: "auth_token".to_string(),
                        location: "cookie".to_string(),
                    },
                    extensions: Object::default(),
                };
                let mut security_req = SecurityRequirement::new();
                security_req.insert("JWT Token".to_owned(), Vec::new());
                Ok(RequestHeaderInput::Security(
                    "JWT Token".to_owned(),
                    security_scheme,
                    security_req,
                ))
            }
        }
    };
}

static JTI_STORE: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| {
    RwLock::new(HashSet::new())
});

/// Struct for Rocket guard
pub struct Authenticated {
    pub claims: Claims,
}

pub struct AuthenticatedPrivileged {
    pub _claims: Claims,
}

/// Service-token-only claim block (absent for human tokens).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct ServiceClaims {
    pub(crate) account_id: i64,
    pub(crate) scopes: Vec<String>,
}

/// JWT claims
#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct Claims {
    pub(crate) jti: String,
    pub(crate) id: i64,
    pub(crate) role: UserRole,
    pub(crate) exp: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) service: Option<ServiceClaims>,
    #[serde(default)]
    pub(crate) is_local: bool,
}

impl Claims {
    pub(crate) fn is_service(&self) -> bool {
        self.service.is_some()
    }
    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        self.service
            .as_ref()
            .is_some_and(|s| s.scopes.iter().any(|x| x == scope))
    }
    pub(crate) fn is_local_admin(&self) -> bool {
        !self.is_service() && self.role == UserRole::Admin && self.is_local
    }
}

/// Rocket guard implementation
/// Authenticate user through auth_token cookie
#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authenticated {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match authenticate_auth_token(request) {
            Some(claims) => Outcome::Success(Authenticated { claims }),
            None => Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

impl_openapi_auth!(Authenticated, "UserRole::User");

/// Rocket guard implementation
/// Authenticate user through auth_token cookie, requiring UserRole::Admin
#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedPrivileged {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(claims) =  authenticate_auth_token(request) else { return Outcome::Error((Status::Unauthorized, ())) };
        if claims.role == UserRole::Admin {
            Outcome::Success(AuthenticatedPrivileged { _claims: claims })
        } else {
            Outcome::Error((Status::Forbidden, ()))
        }
    }
}

impl_openapi_auth!(AuthenticatedPrivileged, "UserRole::Admin");

pub struct AuthenticatedLocalAdmin {
    pub _claims: Claims,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedLocalAdmin {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(claims) = authenticate_auth_token(request) else { return Outcome::Error((Status::Unauthorized, ())) };
        if claims.is_local_admin() {
            Outcome::Success(AuthenticatedLocalAdmin { _claims: claims })
        } else {
            Outcome::Error((Status::Forbidden, ()))
        }
    }
}

impl_openapi_auth!(AuthenticatedLocalAdmin, "local UserRole::Admin");

pub(crate) fn authenticate_auth_token(request: &Request<'_>) -> Option<Claims> {
    // Prefer an explicit Authorization: Bearer header (service tokens) over the private
    // cookie (human sessions). A non-Bearer Authorization header is ignored and we fall
    // back to the cookie, so it cannot break human cookie authentication.
    let token = match request
        .headers()
        .get_one("Authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
    {
        Some(bearer) => bearer.trim().to_string(),
        None => request.cookies().get_private("auth_token")?.value().to_string(),
    };

    let config = request.rocket().state::<AppState>()?;
    let jwt_key = config.settings.get_jwt_key().ok()?;
    let decoding_key = DecodingKey::from_secret(&jwt_key);
    let validation = Validation::default();

    let claims = decode::<Claims>(&token, &decoding_key, &validation).ok()?.claims;

    // Service tokens are stateless — no JTI membership requirement.
    if claims.service.is_some() {
        return Some(claims);
    }

    match JTI_STORE.read().contains(&claims.jti) {
        true => Some(claims),
        false => None,
    }
}

/// Generate JWT Token for authentication
pub(crate) fn generate_token(jwt_key: &[u8], user_id: i64, user_role: UserRole, is_local: bool) -> Result<String, ApiError> {
    let expires = SystemTime::now() + Duration::from_secs(60 * 60 /* 1 hour */);
    let expires_unix = expires.duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let jti = Uuid::new_v4().to_string();

    let claims = Claims {
        jti: jti.clone(),
        exp: expires_unix,
        id: user_id,
        role: user_role,
        service: None,
        is_local,
    };

    JTI_STORE.write().insert(jti);

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_key),
    ).map_err(|_| ApiError::Other("Failed to generate JWT".to_string()))
}

/// Build a stateless service JWT: id = owner user, role = User, carries scopes.
/// NOT registered in JTI_STORE (survives restarts; revoked via DB flag + short exp).
pub(crate) fn generate_service_token(
    jwt_key: &[u8],
    owner_user_id: i64,
    account_id: i64,
    scopes: Vec<String>,
) -> Result<String, ApiError> {
    let expires = SystemTime::now() + Duration::from_secs(60 * 60 /* 1 hour */);
    let expires_unix = expires.duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let claims = Claims {
        jti: Uuid::new_v4().to_string(),
        exp: expires_unix,
        id: owner_user_id,
        role: UserRole::User,
        service: Some(ServiceClaims { account_id, scopes }),
        is_local: false,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_key),
    )
    .map_err(|_| ApiError::Other("Failed to generate service JWT".to_string()))
}

pub(crate) fn invalidate_token(jti: &str) {
    JTI_STORE.write().remove(jti);
}

#[cfg(test)]
mod service_token_tests {
    use super::*;

    #[test]
    fn service_token_carries_scopes_and_user_role() {
        let key = b"0123456789abcdef0123456789abcdef";
        let token = generate_service_token(key, 7, 3, vec!["cert:read".into()]).unwrap();
        let claims = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(key),
            &Validation::default(),
        )
        .unwrap()
        .claims;
        assert_eq!(claims.id, 7);
        assert_eq!(claims.role, UserRole::User);
        assert!(claims.is_service());
        assert!(claims.has_scope("cert:read"));
        assert!(!claims.has_scope("cert:issue"));
    }

    #[test]
    fn old_token_without_is_local_defaults_false() {
        // токен, закодированный без поля is_local, должен декодироваться в is_local=false
        let key = b"0123456789abcdef0123456789abcdef";
        #[derive(serde::Serialize)]
        struct OldClaims { jti: String, id: i64, role: u8, exp: usize }
        let old = OldClaims { jti: "j".into(), id: 1, role: 1, exp: 9_999_999_999 };
        let token = encode(&Header::default(), &old, &EncodingKey::from_secret(key)).unwrap();
        let claims = decode::<Claims>(&token, &DecodingKey::from_secret(key), &Validation::default()).unwrap().claims;
        assert!(!claims.is_local);
    }

    #[test]
    fn is_local_admin_classification() {
        let admin_local = Claims { jti: "a".into(), id: 1, role: UserRole::Admin, exp: 0, service: None, is_local: true };
        let admin_oidc  = Claims { jti: "b".into(), id: 2, role: UserRole::Admin, exp: 0, service: None, is_local: false };
        let user_local  = Claims { jti: "c".into(), id: 3, role: UserRole::User,  exp: 0, service: None, is_local: true };
        assert!(admin_local.is_local_admin());
        assert!(!admin_oidc.is_local_admin());
        assert!(!user_local.is_local_admin());
    }
}