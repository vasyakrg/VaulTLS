use crate::acme_client::client;
use crate::certs::tls_cert::{get_dns_names, TLSCertificateBuilder};
use crate::data::enums::{CertificateRenewMethod, UserRole};
use crate::data::enums::CertificateType::*;
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
                } else if cert.valid_until < in_a_week
                    && handle_expiry(cert, &db, mailer_mutex.clone()).await.is_ok()
                {
                    let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
                }
            }
        } else {
            info!("Failed to get certificates from database.");
        }

        ticker.tick().await;
    }
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

            let mut new_cert = match cert.certificate_type {
                TLSClient | TLSServer => {
                    let ca = db.get_latest_tls_ca().await?;
                    let cert_builder = TLSCertificateBuilder::try_from(cert)?
                        .set_ca(&ca)?;

                    if cert.certificate_type == TLSClient {
                        cert_builder
                            .set_email_san(&user.email)?
                            .build_client()?
                    } else {
                        let dns = get_dns_names(cert)?;
                        cert_builder
                            .set_dns_san(&dns)?
                            .build_server()?
                    }
                }
                SSHClient | SSHServer => {
                    return Err(anyhow!("SSH not supported for renewal."));
                }
            };

            new_cert = db.insert_user_cert(new_cert).await?;

            if cert.renew_method == CertificateRenewMethod::RenewAndNotify {
                info!("Notifying user {} that cert {} was renewed.", user.name, cert.name);
                let mail = MailMessage {
                    to: format!("{} <{}>", user.name, user.email),
                    username: user.name,
                    certificate: new_cert.clone()
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
