use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rocket::{delete, get, post, State};
use rocket::serde::json::Json;
use rocket_okapi::openapi;
use crate::acme_client::types::{AcmeClientProvider, CreateProviderRequest};
use crate::auth::session_auth::AuthenticatedPrivileged;
use crate::data::error::ApiError;
use crate::data::objects::AppState;

#[openapi(tag = "ACME Client")]
#[get("/acme-client/providers")]
pub async fn get_acme_client_providers(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
) -> Result<Json<Vec<AcmeClientProvider>>, ApiError> {
    Ok(Json(state.db.get_all_acme_client_providers().await?))
}

#[openapi(tag = "ACME Client")]
#[post("/acme-client/providers", format = "json", data = "<req>")]
pub async fn create_acme_client_provider(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    req: Json<CreateProviderRequest>,
) -> Result<Json<AcmeClientProvider>, ApiError> {
    let eab_hmac_key = match &req.eab_hmac_key {
        Some(b64) => Some(
            URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|_| ApiError::BadRequest("invalid eab_hmac_key".into()))?,
        ),
        None => None,
    };
    let provider = state.db
        .insert_acme_client_provider(
            req.name.clone(),
            req.directory_url.clone(),
            req.account_email.clone(),
            req.eab_kid.clone(),
            eab_hmac_key,
        )
        .await?;
    Ok(Json(provider))
}

#[openapi(tag = "ACME Client")]
#[delete("/acme-client/providers/<id>")]
pub async fn delete_acme_client_provider(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
) -> Result<(), ApiError> {
    state.db.delete_acme_client_provider(id).await?;
    Ok(())
}
