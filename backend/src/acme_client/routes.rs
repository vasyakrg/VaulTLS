use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rocket::{delete, get, post, put, State};
use rocket::serde::json::Json;
use rocket_okapi::openapi;
use crate::acme_client::types::{AcmeClientOrder, AcmeClientProvider, CreateOrderRequest, CreateOrderResponse, CreateProviderRequest, UpdateProviderRequest};
use crate::acme_client::client;
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

#[openapi(tag = "ACME Client")]
#[put("/acme-client/providers/<id>", format = "json", data = "<req>")]
pub async fn update_acme_client_provider(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
    req: Json<UpdateProviderRequest>,
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
        .update_acme_client_provider(
            id,
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
#[get("/acme-client/orders")]
pub async fn get_acme_client_orders(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
) -> Result<Json<Vec<AcmeClientOrder>>, ApiError> {
    Ok(Json(state.db.get_all_acme_client_orders().await?))
}

#[openapi(tag = "ACME Client")]
#[post("/acme-client/orders", format = "json", data = "<req>")]
pub async fn create_acme_client_order(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    req: Json<CreateOrderRequest>,
) -> Result<Json<CreateOrderResponse>, ApiError> {
    let provider = state.db.get_acme_client_provider(req.provider_id).await?;
    let created = client::create_order(&provider, &req.domain, req.include_wildcard)
        .await
        .map_err(|e| ApiError::Other(e.to_string()))?;
    if let Some(creds) = created.account_credentials {
        state.db.update_acme_client_provider_credentials(provider.id, creds).await?;
    }
    let order = state.db.insert_acme_client_order(
        provider.id, req.domain.clone(), req.include_wildcard,
        Some(created.order_url), &created.txt_records, created.expires_at,
    ).await?;
    Ok(Json(CreateOrderResponse { order_id: order.id, txt_records: order.txt_records }))
}

#[openapi(tag = "ACME Client")]
#[post("/acme-client/orders/<id>/issue")]
pub async fn issue_acme_client_order(
    state: &State<AppState>,
    auth: AuthenticatedPrivileged,
    id: i64,
) -> Result<Json<AcmeClientOrder>, ApiError> {
    let order = state.db.get_acme_client_order(id).await?;
    // Allow issuance from pending_dns/ready and retry from a previous `failed`
    // attempt (a failed DNS pre-check is transient — the ACME order URL stays
    // valid for ~7 days, so the user can re-run once the TXT records propagate).
    // Block only `valid` (already issued) and `expired` (order URL no longer usable).
    if order.status != "pending_dns" && order.status != "ready" && order.status != "failed" {
        return Err(ApiError::BadRequest(format!(
            "order {} is not awaiting issuance (status: {})", id, order.status
        )));
    }
    let provider = state.db.get_acme_client_provider(order.provider_id).await?;
    let order_url = order.order_url.clone()
        .ok_or_else(|| ApiError::BadRequest("order has no URL".into()))?;

    let result = client::issue_order(&provider, &order_url, &order.domain, &order.txt_records).await;
    match result {
        Ok(issued) => {
            let inner = async {
                let packed = client::pack_issued_certificate(&issued.certificate_pem, &issued.private_key_pem, "")
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let cert_name = if order.include_wildcard {
                    crate::data::objects::Name::from(
                        format!("{}, *.{}", order.domain, order.domain).as_str()
                    )
                } else {
                    crate::data::objects::Name::from(order.domain.as_str())
                };
                let cert_id = state.db.insert_acme_client_certificate(
                    cert_name,
                    packed.pkcs12_der, "".into(), packed.valid_until, auth._claims.id, provider.id,
                ).await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
                state.db.update_acme_client_order_status(id, "valid", Some(cert_id), None).await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                Ok::<_, anyhow::Error>(())
            }.await;
            if let Err(e) = inner {
                state.db.update_acme_client_order_status(id, "failed", None, Some(e.to_string())).await?;
                return Err(ApiError::Other(e.to_string()));
            }
        }
        Err(e) => {
            state.db.update_acme_client_order_status(id, "failed", None, Some(e.to_string())).await?;
            return Err(ApiError::Other(e.to_string()));
        }
    }
    Ok(Json(state.db.get_acme_client_order(id).await?))
}

#[openapi(tag = "ACME Client")]
#[delete("/acme-client/orders/<id>")]
pub async fn delete_acme_client_order(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
) -> Result<(), ApiError> {
    state.db.delete_acme_client_order(id).await?;
    Ok(())
}
