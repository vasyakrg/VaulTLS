use crate::acme_client::client;
use crate::certs::tls_cert::{get_dns_names, TLSCertificateBuilder};
use crate::data::enums::{AuditAction, AuditActorType, AuditResult, CertificateRenewMethod, UserRole};
use crate::data::enums::CertificateType::*;
use crate::data::objects::AuditEntry;
use crate::db::VaulTLSDB;
use crate::notification::mail::{MailMessage, Mailer};
use std::sync::Arc;
use std::time::Duration;
use anyhow::anyhow;
use tokio::sync::Mutex;
use tokio::time::{interval  , MissedTickBehavior};
use tracing::{info, trace};
use crate::certs::common::Certificate;

/// Notify all admin users that a new ACME certificate was issued.
pub(crate) async fn notify_admins_acme_issued(db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>, cert: Certificate) {
    let Ok(users) = db.get_all_user().await else { return };
    let mailer_guard = mailer_mutex.lock().await;
    let Some(mailer) = &*mailer_guard else { return };
    for user in users.into_iter().filter(|u| u.role == UserRole::Admin) {
        let _ = mailer.notify_acme_certificate_issued(MailMessage {
            to: format!("{} <{}>", user.name, user.email),
            username: user.name,
            certificate: cert.clone(),
        }).await;
    }
}

pub(crate) async fn watch_expiry(db: VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>, settings: crate::settings::Settings) {
    info!("Starting certificate expiry watcher.");
    let interval_secs = std::env::var("VAULTLS_CHECK_EXPIRY_INTERVAL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(300);

    let mut ticker = interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);


    loop {
        trace!("Checking for active certificates that are about to expire.");

        if let Ok(certs) = db.get_user_certs(None, None, Some(false)).await {
            let now = chrono::Utc::now().timestamp_millis();
            let in_a_week = now + 1000 * 60 * 60 * 24 * 7;
            let in_30_days = now + 1000 * 60 * 60 * 24 * 30;
            for cert in certs.iter() {
                if cert.renew_method == CertificateRenewMethod::None {
                    continue;
                }
                if cert.acme_provider_id.is_some() {
                    // ACME certificates never go through the internal-CA renewal path.
                    match cert.renew_method {
                        CertificateRenewMethod::Renew | CertificateRenewMethod::RenewAndNotify => {
                            if cert.valid_until < in_30_days {
                                // Do NOT reset renew_method — auto-renew must keep firing.
                                if let Err(e) = handle_acme_renewal(cert, &db, &settings, mailer_mutex.clone()).await {
                                    info!("ACME renewal for cert {} failed: {e}", cert.id);
                                }
                            }
                        }
                        CertificateRenewMethod::Notify => {
                            if cert.valid_until < in_a_week
                                && handle_expiry(cert, &db, mailer_mutex.clone()).await.is_ok()
                            {
                                let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
                            }
                        }
                        CertificateRenewMethod::None => {}
                    }
                } else if cert.is_imported {
                    // Imported certificates carry material the operator obtained
                    // elsewhere (Let's Encrypt, corporate PKI, ...) — the internal CA
                    // must never silently overwrite it in place, no matter what
                    // renew_method says. Route it through the expiry notice instead
                    // (same as Notify below) and reset renew_method afterwards so the
                    // mail fires once; the owner replaces it by hand via PUT
                    // /certificates/<id>, which is exactly what that endpoint is for.
                    if cert.valid_until < in_a_week
                        && handle_imported_expiry(cert, &db, mailer_mutex.clone()).await.is_ok()
                    {
                        let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
                    }
                } else {
                    // Internal-CA path: Renew/RenewAndNotify now replace the certificate
                    // in place (see handle_expiry), so the row keeps renewing on every
                    // expiry instead of forking a new id — do NOT reset renew_method for
                    // it, mirroring the ACME branch above. Only Notify is one-shot.
                    match cert.renew_method {
                        CertificateRenewMethod::Renew | CertificateRenewMethod::RenewAndNotify => {
                            if cert.valid_until < in_a_week {
                                if let Err(e) = handle_expiry(cert, &db, mailer_mutex.clone()).await {
                                    info!("Renewal for cert {} failed: {e}", cert.id);
                                }
                            }
                        }
                        CertificateRenewMethod::Notify => {
                            if cert.valid_until < in_a_week
                                && handle_expiry(cert, &db, mailer_mutex.clone()).await.is_ok()
                            {
                                let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
                            }
                        }
                        CertificateRenewMethod::None => {}
                    }
                }
            }
        } else {
            info!("Failed to get certificates from database.");
        }

        ticker.tick().await;
    }
}

/// Notifies the owner that an imported certificate is expiring. Never renews it — an
/// imported row's material came from outside VaulTLS, and the internal CA overwriting
/// it in place would be a silent, unwanted substitution. This is the safety net for
/// `is_imported` certificates regardless of what their `renew_method` says; the actual
/// `Renew`/`RenewAndNotify`/`Notify` distinction only applies to internally-issued rows
/// handled by `handle_expiry` below.
async fn handle_imported_expiry(cert: &Certificate, db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>) -> Result<(), anyhow::Error> {
    let user = db.get_user(cert.user_id).await?;
    info!(
        "Imported certificate {} owned by user {} is about to expire; internal CA will not renew it, notifying instead.",
        cert.name, user.name
    );
    let mail = MailMessage {
        to: format!("{} <{}>", user.name, user.email),
        username: user.name,
        certificate: cert.clone()
    };

    tokio::spawn(async move {
        if let Some(mailer) = &mut *mailer_mutex.lock().await {
            let _ = mailer.notify_old_certificate(mail).await;
        }
    });

    Ok(())
}

async fn handle_expiry(cert: &Certificate, db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>) -> Result<(), anyhow::Error> {
    let user = db.get_user(cert.user_id).await?;
    info!("Certificate {} owned by user {} is about to expire.", cert.name, user.name);

    match cert.renew_method {
        CertificateRenewMethod::Notify => {
            info!("Notifying user {}.", user.name);
            let mail = MailMessage {
                to: format!("{} <{}>", user.name, user.email),
                username: user.name,
                certificate: cert.clone()
            };

            tokio::spawn(async move {
                if let Some(mailer) = &mut *mailer_mutex.lock().await {
                    let _ = mailer.notify_old_certificate(mail).await;
                }
            });
        }
        CertificateRenewMethod::Renew | CertificateRenewMethod::RenewAndNotify => {
            info!("Renewing certificate {} for user {}.", cert.name, user.name);

            // ca_id is captured alongside the built certificate: get_latest_tls_ca may
            // return a different CA than the one that originally signed `cert`, and the
            // replaced row must be repointed at whoever actually signed the renewal.
            let (new_cert, ca_id) = match cert.certificate_type {
                TLSClient | TLSServer => {
                    let ca = db.get_latest_tls_ca().await?;
                    let ca_id = ca.id;
                    let cert_builder = TLSCertificateBuilder::try_from(cert)?
                        .set_ca(&ca)?;

                    let built = if cert.certificate_type == TLSClient {
                        cert_builder
                            .set_email_san(&user.email)?
                            .build_client()?
                    } else {
                        let dns = get_dns_names(cert)?;
                        cert_builder
                            .set_dns_san(&dns)?
                            .build_server()?
                    };
                    (built, ca_id)
                }
                SSHClient | SSHServer => {
                    return Err(anyhow!("SSH not supported for renewal."));
                }
            };

            // Same row, new content: the renewed material replaces the current version
            // in place and the expiring one moves into certificate_versions history, so
            // any agent polling by cert_id keeps tracking the same id.
            let fingerprint = new_cert.get_fingerprint()
                .map_err(|e| anyhow!("cannot compute fingerprint for renewed cert: {e}"))?;
            let serial_hex = new_cert.get_serial().ok()
                .map(|s| s.iter().map(|b| format!("{b:02x}")).collect::<String>());

            let new_version = db.replace_certificate(
                cert.id,
                // No human actor performed this replacement — it's unattended. NULL
                // here (not cert.user_id) so `replaced_by`, which the version-history
                // API and UI expose as "who did this", does not falsely attribute an
                // automatic renewal to the owner.
                None,
                crate::db::ReplaceCertificateInput {
                    data: new_cert.data.as_bytes().to_vec(),
                    password: new_cert.password.clone(),
                    created_on: new_cert.created_on,
                    valid_until: new_cert.valid_until,
                    serial_hex,
                    fingerprint,
                    ca_id,
                },
                crate::db::ReplaceGuard::Renewal,
            ).await?;

            // The action still needs to be visible somewhere audit-relevant. VaulTLS has
            // no "system" actor concept (AuditActorType is User | Service | Anonymous —
            // see backend/src/data/enums.rs), so this records the certificate's owner as
            // actor and says explicitly in `detail` that it was an unattended renewal,
            // rather than inventing a new actor-type variant here.
            let audit_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            if let Err(e) = db.insert_audit(AuditEntry {
                ts: audit_ts,
                actor_id: Some(cert.user_id),
                actor_label: user.name.clone(),
                actor_type: AuditActorType::User,
                action: AuditAction::UpdateCertificate,
                target_type: Some("certificate".into()),
                target_id: Some(cert.id.to_string()),
                target_label: Some(cert.name.cn.clone()),
                result: AuditResult::Success,
                detail: Some(format!("automatic renewal by internal CA: v{} → v{new_version}", cert.version)),
                ip: None,
            }).await {
                tracing::warn!(error = %e, cert_id = cert.id, "failed to write audit log entry for certificate renewal");
            }

            if cert.renew_method == CertificateRenewMethod::RenewAndNotify {
                // Re-read the row: it now carries the renewed contents under the same id.
                let renewed_cert = db.get_user_cert_by_id(cert.id).await?;
                info!("Notifying user {} that cert {} was renewed.", user.name, cert.name);
                let mail = MailMessage {
                    to: format!("{} <{}>", user.name, user.email),
                    username: user.name,
                    certificate: renewed_cert
                };

                tokio::spawn(async move {
                    if let Some(mailer) = &mut *mailer_mutex.lock().await {
                        let _ = mailer.notify_renewed_certificate(mail).await;
                    }
                });
            }
        }
        CertificateRenewMethod::None => {}
    }

    Ok(())
}

async fn handle_acme_renewal(
    cert: &Certificate,
    db: &VaulTLSDB,
    settings: &crate::settings::Settings,
    mailer_mutex: Arc<Mutex<Option<Mailer>>>,
) -> Result<(), anyhow::Error> {
    // Dedup guard: don't create a second renewal order while one is still in flight.
    let now_ms = chrono::Utc::now().timestamp_millis();
    if db.get_active_renewal_order_for_cert(cert.id, now_ms).await?.is_some() {
        return Ok(());
    }

    // Derive domain/provider/wildcard from the order that originally produced this cert.
    let source = db
        .get_acme_client_order_by_cert_id(cert.id)
        .await?
        .ok_or_else(|| anyhow!("no source order found for cert {}", cert.id))?;
    let provider = db.get_acme_client_provider(source.provider_id).await?;

    let created = client::create_order(&provider, &source.domain, source.include_wildcard).await?;
    if let Some(creds) = created.account_credentials {
        db.update_acme_client_provider_credentials(provider.id, creds).await?;
    }
    let order = db
        .insert_acme_client_order(
            provider.id,
            source.domain.clone(),
            source.include_wildcard,
            Some(created.order_url.clone()),
            &created.txt_records,
            created.expires_at,
            Some(cert.id),
        )
        .await?;

    if created.txt_records.is_empty() {
        // Authorization still valid at the CA — renew unattended.
        let resolver = settings.get_acme_dns_resolver();
        let accept_invalid = settings.get_acme_accept_invalid_certs();
        let issued = client::issue_order(
            &provider,
            &created.order_url,
            &source.domain,
            &created.txt_records,
            &resolver,
            accept_invalid,
        )
        .await?;
        let packed = client::pack_issued_certificate(&issued.certificate_pem, &issued.private_key_pem, "")?;
        db.update_acme_client_certificate_in_place(cert.id, packed.pkcs12_der, packed.valid_until).await?;
        db.update_acme_client_order_status(order.id, "valid", Some(cert.id), None).await?;

        if cert.renew_method == CertificateRenewMethod::RenewAndNotify {
            let user = db.get_user(cert.user_id).await?;
            let mail = MailMessage {
                to: format!("{} <{}>", user.name, user.email),
                username: user.name,
                certificate: cert.clone(),
            };
            tokio::spawn(async move {
                if let Some(mailer) = &mut *mailer_mutex.lock().await {
                    let _ = mailer.notify_renewed_certificate(mail).await;
                }
            });
        }
    } else {
        // Fresh challenge needed — leave the order pending_dns and tell the user to publish TXT.
        info!(
            "ACME renewal for cert {} needs new TXT records; order {} left pending_dns.",
            cert.id, order.id
        );
        let user = db.get_user(cert.user_id).await?;
        let mail = MailMessage {
            to: format!("{} <{}>", user.name, user.email),
            username: user.name,
            certificate: cert.clone(),
        };
        tokio::spawn(async move {
            if let Some(mailer) = &mut *mailer_mutex.lock().await {
                let _ = mailer.notify_old_certificate(mail).await;
            }
        });
    }

    Ok(())
}
