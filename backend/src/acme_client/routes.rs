use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rocket::{delete, get, post, put, State};
use rocket::serde::json::Json;
use rocket_okapi::openapi;
use crate::acme_client::types::{AcmeClientOrder, AcmeClientProvider, CreateOrderRequest, CreateOrderResponse, CreateProviderRequest, DnsCheckResponse, UpdateProviderRequest};
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
    if let Some(renew_id) = req.renews_cert_id {
        let target = state.db.get_user_cert_by_id(renew_id).await
            .map_err(|_| ApiError::BadRequest("renews_cert_id refers to an unknown certificate".into()))?;
        if target.acme_provider_id != Some(provider.id) {
            return Err(ApiError::BadRequest(
                "renews_cert_id must reference an ACME certificate issued by the same provider".into(),
            ));
        }
    }
    let created = client::create_order(&provider, &req.domain, req.include_wildcard)
        .await
        .map_err(|e| ApiError::Other(e.to_string()))?;
    if let Some(creds) = created.account_credentials {
        state.db.update_acme_client_provider_credentials(provider.id, creds).await?;
    }
    let order = state.db.insert_acme_client_order(
        provider.id, req.domain.clone(), req.include_wildcard,
        Some(created.order_url), &created.txt_records, created.expires_at, req.renews_cert_id,
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

    let resolver_addr = state.settings.get_acme_dns_resolver();
    let accept_invalid_certs = state.settings.get_acme_accept_invalid_certs();
    let result = client::issue_order(
        &provider, &order_url, &order.domain, &order.txt_records,
        &resolver_addr, accept_invalid_certs,
    ).await;
    match result {
        Ok(issued) => {
            let inner = async {
                let packed = client::pack_issued_certificate(&issued.certificate_pem, &issued.private_key_pem, "")
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                // Filled in on the renewal branch below; carries what the audit record
                // needs. Fired after the order status update further down, not here —
                // see the comment at that call for why.
                let mut renewal_audit: Option<(i64, i64, String, String)> = None;
                let result_cert_id = if let Some(renew_id) = order.renews_cert_id {
                    // Renewal: replace the existing certificate in place (same id) and
                    // push the superseded content into certificate_versions, mirroring
                    // the unattended ACME renewal path in
                    // notification::notifier::handle_acme_renewal — same guard, same
                    // "leave ca_id alone" reasoning. Unlike that path, this one runs
                    // under AuthenticatedPrivileged: a person pressed "issue", so
                    // attribution below is a real actor, not the system.
                    let existing = state.db.get_user_cert_by_id(renew_id).await
                        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    let tmp_cert = crate::certs::common::Certificate {
                        data: crate::data::enums::CertData::Pkcs12(packed.pkcs12_der.clone()),
                        password: String::new(),
                        valid_until: packed.valid_until,
                        ..existing.clone()
                    };
                    let fingerprint = tmp_cert.get_fingerprint()
                        .map_err(|e| anyhow::anyhow!("cannot compute fingerprint for renewed ACME cert: {e}"))?;
                    let serial_hex = tmp_cert.get_serial().ok()
                        .map(|s| s.iter().map(|b| format!("{b:02x}")).collect::<String>());
                    let created_on = chrono::Utc::now().timestamp_millis();

                    // No map_err(..to_string()) here, unlike the other calls in this
                    // block: replace_certificate's CertificateNotReplaceable needs to
                    // survive as its concrete type so the outer handler below can
                    // downcast it into a 409, the same way api::update_certificate
                    // does for the identical race. Wrapping it through a String here
                    // would erase that.
                    let new_version = state.db.replace_certificate(
                        renew_id,
                        // A person triggered this via the UI/API — attribute it to
                        // them, matching what the manual replace endpoint
                        // (api::update_certificate) records for `replaced_by`.
                        Some(auth.claims.id),
                        crate::db::ReplaceCertificateInput {
                            data: packed.pkcs12_der,
                            // pack_issued_certificate above is always called with "".
                            password: String::new(),
                            created_on,
                            valid_until: packed.valid_until,
                            serial_hex,
                            fingerprint: fingerprint.clone(),
                            // ACME certificates carry ca_id = NULL and must keep it;
                            // 0 means "leave the existing binding alone".
                            ca_id: 0,
                        },
                        crate::db::ReplaceGuard::AcmeRenewal,
                    ).await?;

                    renewal_audit = Some((existing.version, new_version, fingerprint, existing.name.cn.clone()));
                    renew_id
                } else {
                    let cert_name = if order.include_wildcard {
                        crate::data::objects::Name::from(
                            format!("{}, *.{}", order.domain, order.domain).as_str()
                        )
                    } else {
                        crate::data::objects::Name::from(order.domain.as_str())
                    };
                    state.db.insert_acme_client_certificate(
                        cert_name,
                        packed.pkcs12_der, "".into(), packed.valid_until, auth.claims.id, provider.id,
                    ).await.map_err(|e| anyhow::anyhow!(e.to_string()))?
                };
                state.db.update_acme_client_order_status(id, "valid", Some(result_cert_id), None).await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

                // Replace → status → audit, same ordering as
                // notifier.rs::handle_acme_renewal. Audit fires only after the order
                // status update above has actually succeeded — otherwise a failed
                // status update below would still leave a Success audit row on record
                // for a replacement whose order bookkeeping never completed.
                if let Some((old_version, new_version, fingerprint, cn)) = renewal_audit {
                    // Same shape as api::update_certificate's audit call: real actor
                    // via audit_actor/record_audit, AuditAction::UpdateCertificate,
                    // detail names the version transition — just labelled as an ACME
                    // renewal instead of a manual replace.
                    let (aid, alabel, atype) = crate::api::audit_actor(state, &auth.claims).await;
                    crate::api::record_audit(
                        state, aid, alabel, atype, crate::data::enums::AuditAction::UpdateCertificate,
                        Some("certificate".into()), Some(result_cert_id.to_string()), Some(cn),
                        crate::data::enums::AuditResult::Success,
                        Some(format!("ACME renewal: v{old_version} → v{new_version}, fingerprint {fingerprint}")),
                        None,
                    ).await;
                }

                Ok::<_, anyhow::Error>(())
            }.await;
            if let Err(e) = inner {
                state.db.update_acme_client_order_status(id, "failed", None, Some(e.to_string())).await?;
                // Same downcast api::update_certificate performs on replace_certificate's
                // error (backend/src/api.rs:979-987): the row stopped matching the
                // AcmeRenewal guard between the order and this write (e.g. revoked
                // concurrently) is a state conflict, not an internal error — 409, not 500.
                if e.downcast_ref::<crate::db::CertificateNotReplaceable>().is_some() {
                    return Err(ApiError::Conflict("certificate state changed and it can no longer be replaced".into()));
                }
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
#[post("/acme-client/orders/<id>/check-dns")]
pub async fn check_acme_client_order_dns(
    state: &State<AppState>,
    _auth: AuthenticatedPrivileged,
    id: i64,
) -> Result<Json<DnsCheckResponse>, ApiError> {
    let order = state.db.get_acme_client_order(id).await?;
    let resolver_addr = state.settings.get_acme_dns_resolver();
    let accept_invalid_certs = state.settings.get_acme_accept_invalid_certs();

    // Resolver-only visibility check. Never contacts the CA and never mutates order status.
    match client::check_txt_records(&order.domain, &order.txt_records, &resolver_addr, accept_invalid_certs).await {
        Ok(outcome) => Ok(Json(DnsCheckResponse {
            ok: outcome.ok,
            expected: outcome.expected,
            found: outcome.found,
            missing: outcome.missing,
            error: None,
        })),
        // A lookup failure is surfaced in-band (200 + error) so the UI can render the reason
        // in the modal instead of showing a generic 500.
        Err(e) => Ok(Json(DnsCheckResponse {
            ok: false,
            expected: order.txt_records.iter().map(|r| r.value.clone()).collect(),
            found: vec![],
            missing: order.txt_records.iter().map(|r| r.value.clone()).collect(),
            error: Some(e.to_string()),
        })),
    }
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
