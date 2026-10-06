use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::Rng;
use rocket::{delete, get, post, put, State};
use rocket::serde::json::Json;
use rocket_okapi::openapi;
use crate::acme::guard::AcmeEnabled;
use crate::acme::types::{AcmeAccount, AdminAcmeOrder, CreateAcmeAccountRequest, CreateAcmeAccountResponse, UpdateAcmeAccountRequest};
use crate::api::{audit_actor, record_audit, revoke_cert_and_update_crl};
use crate::auth::session_auth::{AuthenticatedLocalAdmin, AuthenticatedPrivileged};
use crate::data::enums::{AuditAction, AuditResult};
use crate::data::error::ApiError;
use crate::data::objects::AppState;
use uuid::Uuid;

#[openapi(tag = "ACME")]
#[get("/acme/orders")]
pub async fn get_acme_orders(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    _acme: AcmeEnabled,
) -> Result<Json<Vec<AdminAcmeOrder>>, ApiError> {
    let orders = state.db.get_all_acme_orders().await?;
    Ok(Json(orders))
}

#[openapi(tag = "ACME")]
#[get("/acme/accounts")]
pub async fn get_acme_accounts(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    _acme: AcmeEnabled,
) -> Result<Json<Vec<AcmeAccount>>, ApiError> {
    let accounts = state.db.get_all_acme_accounts().await?;
    Ok(Json(accounts))
}

#[openapi(tag = "ACME")]
#[post("/acme/accounts", format = "json", data = "<req>")]
pub async fn create_acme_account(
    state: &State<AppState>,
    auth: AuthenticatedPrivileged,
    req: Json<CreateAcmeAccountRequest>,
    _acme: AcmeEnabled,
) -> Result<Json<CreateAcmeAccountResponse>, ApiError> {
    let eab_kid = Uuid::new_v4().to_string();

    let mut eab_hmac_key = vec![0u8; 32];
    rand::rng().fill_bytes(eab_hmac_key.as_mut_slice());

    let allowed_domains = req.allowed_domains.join(",");

    let account = state.db.insert_acme_account(
        req.name.clone(),
        allowed_domains,
        eab_kid.clone(),
        eab_hmac_key.clone(),
        req.ca_id,
        auth.claims.id,
        req.auto_validate,
    ).await?;

    Ok(Json(CreateAcmeAccountResponse {
        id: account.id,
        name: account.name,
        eab_kid,
        eab_hmac_key: URL_SAFE_NO_PAD.encode(&eab_hmac_key),
    }))
}

#[openapi(tag = "ACME")]
#[put("/acme/accounts/<id>", format = "json", data = "<req>")]
pub async fn update_acme_account(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
    req: Json<UpdateAcmeAccountRequest>,
    _acme: AcmeEnabled,
) -> Result<Json<AcmeAccount>, ApiError> {
    let allowed_domains = req.allowed_domains.as_ref().map(|d| d.join(","));

    state.db.update_acme_account(
        id,
        req.name.clone(),
        allowed_domains,
        req.ca_id.map(Some),  // Some(Some(x)) = set to x; None = don't change
        None,
        req.auto_validate,
    ).await?;

    let account = state.db.get_acme_account(id).await?;
    Ok(Json(account))
}

#[openapi(tag = "ACME")]
#[delete("/acme/accounts/<id>")]
pub async fn delete_acme_account(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<(), ApiError> {
    state.db.update_acme_account(id, None, None, None, Some("deactivated".to_string()), None).await?;
    Ok(())
}

/// Полное удаление деактивированного ACME-аккаунта вместе с его заказами.
/// Выпущенные сертификаты остаются (связь с аккаунтом сбрасывается).
#[openapi(tag = "ACME")]
#[delete("/acme/accounts/<id>/purge")]
pub async fn purge_acme_account(
    state: &State<AppState>,
    auth: AuthenticatedLocalAdmin,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<(), ApiError> {
    let account = state.db.get_acme_account(id).await
        .map_err(|_| ApiError::NotFound(None))?;
    if account.status != "deactivated" {
        return Err(ApiError::BadRequest(
            "only deactivated ACME accounts can be purged; deactivate it first".into(),
        ));
    }

    state.db.delete_acme_account(id).await?;

    let (aid, alabel, atype) = audit_actor(state, &auth.claims).await;
    record_audit(state, aid, alabel, atype, AuditAction::DeleteAcmeAccount,
        Some("acme_account".into()), Some(id.to_string()), Some(account.name.clone()),
        AuditResult::Success, None, auth.ip.clone()).await;
    Ok(())
}

/// Полное удаление заказа ACME (админская очистка истории заказов).
#[openapi(tag = "ACME")]
#[delete("/acme/orders/<id>")]
pub async fn delete_acme_order(
    state: &State<AppState>,
    auth: AuthenticatedLocalAdmin,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<(), ApiError> {
    let order = state.db.get_acme_order(id).await
        .map_err(|_| ApiError::NotFound(None))?;

    state.db.delete_acme_order(id).await?;

    let label = serde_json::from_str::<Vec<serde_json::Value>>(&order.identifiers).ok()
        .and_then(|ids| ids.first().and_then(|i| i["value"].as_str().map(|s| s.to_string())))
        .unwrap_or_else(|| format!("order #{id}"));
    let (aid, alabel, atype) = audit_actor(state, &auth.claims).await;
    record_audit(state, aid, alabel, atype, AuditAction::DeleteAcmeOrder,
        Some("acme_order".into()), Some(id.to_string()), Some(label),
        AuditResult::Success, None, auth.ip.clone()).await;
    Ok(())
}

/// Отзыв сертификата, выпущенного по заказу ACME (обновляет CRL его CA).
#[openapi(tag = "ACME")]
#[post("/acme/orders/<id>/revoke")]
pub async fn revoke_acme_order(
    state: &State<AppState>,
    auth: AuthenticatedLocalAdmin,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<(), ApiError> {
    let order = state.db.get_acme_order(id).await
        .map_err(|_| ApiError::NotFound(None))?;
    let cert_id = order.certificate_id.ok_or_else(|| ApiError::BadRequest(
        "order has no issued certificate to revoke".into(),
    ))?;

    let cert = revoke_cert_and_update_crl(state, cert_id).await?;

    let (aid, alabel, atype) = audit_actor(state, &auth.claims).await;
    record_audit(state, aid, alabel, atype, AuditAction::RevokeCertificate,
        Some("certificate".into()), Some(cert_id.to_string()), Some(cert.name.cn.clone()),
        AuditResult::Success, Some(format!("via ACME order #{id}")), auth.ip.clone()).await;
    Ok(())
}
