use std::collections::HashMap;
use std::env;
use crate::ApiError;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::{Cookie, SameSite, Status};
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

/// Lifetime of a human session token.
pub(crate) const SESSION_TTL_SECS: u64 = 60 * 60;
/// A cookie-backed session is re-issued once less than this much of its lifetime is left,
/// so an actively browsing user is never dropped mid-session.
const SESSION_RENEW_THRESHOLD_SECS: u64 = 15 * 60;
/// How long a token stays usable after it has been replaced by a renewal, so requests that
/// were already in flight with the previous cookie do not fail.
const SESSION_RENEW_GRACE_SECS: u64 = 60;

/// Valid human session tokens: jti -> unix timestamp after which the entry is dead.
/// The stored expiry is our own revocation clock: it starts out matching the JWT `exp`,
/// is shortened to a grace window when the token is renewed, and lets us prune the map.
static JTI_STORE: Lazy<RwLock<HashMap<String, usize>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Register a session token and drop every entry that has expired meanwhile.
fn register_jti(jti: String, expires_unix: usize) {
    let now = now_secs() as usize;
    let mut store = JTI_STORE.write();
    store.retain(|_, exp| *exp > now);
    store.insert(jti, expires_unix);
}

/// Whether a cookie-backed session is close enough to its expiry to be re-issued.
pub(crate) fn needs_renewal(exp: usize, now: u64) -> bool {
    (exp as u64).saturating_sub(now) < SESSION_RENEW_THRESHOLD_SECS
}

/// Build the `auth_token` cookie with the flags every login path uses.
pub(crate) fn build_auth_cookie(token: String) -> Cookie<'static> {
    let mut cookie = Cookie::build(("auth_token", token))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true);

    if let Ok(insecure) = env::var("VAULTLS_INSECURE") && insecure == "true" {
        cookie = cookie.secure(false);
    }

    cookie.build()
}

/// Struct for Rocket guard
pub struct Authenticated {
    pub claims: Claims,
    /// Client IP for audit rows, resolved once per request (`ip_header`-aware —
    /// the same value the `Option<IpAddr>` extractor hands to login/logout).
    pub ip: Option<String>,
}

pub struct AuthenticatedPrivileged {
    pub claims: Claims,
    pub ip: Option<String>,
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
            Some(claims) => Outcome::Success(Authenticated {
                claims,
                ip: request.client_ip().map(|ip| ip.to_string()),
            }),
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
            Outcome::Success(AuthenticatedPrivileged {
                claims,
                ip: request.client_ip().map(|ip| ip.to_string()),
            })
        } else {
            Outcome::Error((Status::Forbidden, ()))
        }
    }
}

impl_openapi_auth!(AuthenticatedPrivileged, "UserRole::Admin");

pub struct AuthenticatedLocalAdmin {
    pub claims: Claims,
    pub ip: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedLocalAdmin {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(claims) = authenticate_auth_token(request) else { return Outcome::Error((Status::Unauthorized, ())) };
        if claims.is_local_admin() {
            Outcome::Success(AuthenticatedLocalAdmin {
                claims,
                ip: request.client_ip().map(|ip| ip.to_string()),
            })
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
    let (token, from_cookie) = match request
        .headers()
        .get_one("Authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
    {
        Some(bearer) => (bearer.trim().to_string(), false),
        None => (request.cookies().get_private("auth_token")?.value().to_string(), true),
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

    let now = now_secs();
    match JTI_STORE.read().get(&claims.jti) {
        Some(store_exp) if (*store_exp as u64) > now => {}
        _ => return None,
    }

    if from_cookie {
        renew_session_cookie_if_needed(request, &claims, now);
    }

    Some(claims)
}

/// Sliding session: while the user keeps making requests, hand out a fresh `auth_token`
/// cookie before the current one expires. The replaced token stays valid for a short grace
/// window so requests already in flight with the old cookie are not rejected.
fn renew_session_cookie_if_needed(request: &Request<'_>, claims: &Claims, now: u64) {
    if !needs_renewal(claims.exp, now) {
        return;
    }

    let Some(config) = request.rocket().state::<AppState>() else { return };
    let Ok(jwt_key) = config.settings.get_jwt_key() else { return };
    let Ok(token) = generate_token(&jwt_key, claims.id, claims.role, claims.is_local) else { return };

    let grace_exp = (now + SESSION_RENEW_GRACE_SECS) as usize;
    {
        let mut store = JTI_STORE.write();
        if let Some(exp) = store.get_mut(&claims.jti) && *exp > grace_exp {
            *exp = grace_exp;
        }
    }

    request.cookies().add_private(build_auth_cookie(token));
}

/// Generate JWT Token for authentication
pub(crate) fn generate_token(jwt_key: &[u8], user_id: i64, user_role: UserRole, is_local: bool) -> Result<String, ApiError> {
    generate_token_with_ttl(jwt_key, user_id, user_role, is_local, SESSION_TTL_SECS)
}

fn generate_token_with_ttl(jwt_key: &[u8], user_id: i64, user_role: UserRole, is_local: bool, ttl_secs: u64) -> Result<String, ApiError> {
    let expires = SystemTime::now() + Duration::from_secs(ttl_secs);
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

    register_jti(jti, expires_unix);

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

#[cfg(test)]
mod sliding_session_tests {
    use super::*;
    use rocket::http::Cookie;
    use rocket::local::asynchronous::Client;

    #[test]
    fn fresh_token_is_not_renewed() {
        let now = 1_000_000;
        let exp = now as usize + SESSION_TTL_SECS as usize;
        assert!(!needs_renewal(exp, now));
    }

    #[test]
    fn token_inside_threshold_is_renewed() {
        let now = 1_000_000;
        let exp = now as usize + (SESSION_RENEW_THRESHOLD_SECS as usize - 1);
        assert!(needs_renewal(exp, now));
    }

    #[test]
    fn already_expired_token_is_renewed_candidate() {
        // exp in the past: saturating_sub keeps us at 0 instead of wrapping.
        assert!(needs_renewal(500, 1_000_000));
    }

    #[test]
    fn register_jti_prunes_expired_entries() {
        let now = now_secs() as usize;
        let stale = Uuid::new_v4().to_string();
        JTI_STORE.write().insert(stale.clone(), now.saturating_sub(10));
        register_jti(Uuid::new_v4().to_string(), now + 600);
        assert!(!JTI_STORE.read().contains_key(&stale));
    }

    /// Drive a real request through the guard to prove the renewed cookie reaches the
    /// response — a jar mutated inside a request guard is only useful if Rocket flushes it.
    #[tokio::test]
    async fn near_expiry_cookie_is_reissued_on_authenticated_request() {
        let client = Client::tracked(crate::create_test_rocket().await)
            .await
            .expect("test rocket");

        let jwt_key = client
            .rocket()
            .state::<AppState>()
            .unwrap()
            .settings
            .get_jwt_key()
            .unwrap();

        // A session with 5 minutes left — inside the renewal threshold.
        let token = generate_token_with_ttl(&jwt_key, 1, UserRole::Admin, true, 5 * 60).unwrap();

        let response = client
            .get("/api/auth/me")
            .private_cookie(Cookie::new("auth_token", token))
            .dispatch()
            .await;

        // The handler may fail on an empty test database; what matters is that the guard
        // accepted the session and the renewed cookie was flushed into the response.
        assert_ne!(response.status(), Status::Unauthorized);
        assert!(
            response.cookies().get_private("auth_token").is_some(),
            "expected a refreshed auth_token cookie on the response"
        );
    }

    #[tokio::test]
    async fn fresh_cookie_is_left_alone() {
        let client = Client::tracked(crate::create_test_rocket().await)
            .await
            .expect("test rocket");

        let jwt_key = client
            .rocket()
            .state::<AppState>()
            .unwrap()
            .settings
            .get_jwt_key()
            .unwrap();

        let token = generate_token(&jwt_key, 1, UserRole::Admin, true).unwrap();

        let response = client
            .get("/api/auth/me")
            .private_cookie(Cookie::new("auth_token", token))
            .dispatch()
            .await;

        assert_ne!(response.status(), Status::Unauthorized);
        assert!(
            response.cookies().get_private("auth_token").is_none(),
            "a fresh session must not be re-issued on every request"
        );
    }

    #[tokio::test]
    async fn expired_session_answers_with_json_error_body() {
        let client = Client::tracked(crate::create_test_rocket().await)
            .await
            .expect("test rocket");

        let response = client.get("/api/certificates").dispatch().await;

        assert_eq!(response.status(), Status::Unauthorized);
        let body = response.into_string().await.unwrap_or_default();
        assert!(
            body.contains("\"error\""),
            "401 body must carry an `error` field, got: {body}"
        );
    }
}