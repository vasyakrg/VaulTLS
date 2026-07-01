use std::{env, fs};
use std::os::unix::prelude::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use rocket::{get, routes, Build, Config, Rocket};
use rocket::fairing::AdHoc;
use rocket_okapi::openapi_get_routes;
use rocket::http::ContentType;
use rocket::response::content::RawHtml;
use tokio::sync::Mutex;
use tracing::{debug, info, trace};
use tracing_subscriber::EnvFilter;
use crate::acme::admin::*;
use crate::acme_client::routes::*;
use crate::api::*;
use crate::auth::oidc_auth::OidcAuth;
use crate::auth::password_auth::Password;
use crate::certs::tls_cert::migrate_ca_storage;
use crate::constants::{API_PORT, DB_FILE_PATH, VAULTLS_VERSION};
use crate::data::objects::AppState;
use crate::db::VaulTLSDB;
use crate::helper::get_secret;
use crate::notification::mail::Mailer;
use crate::notification::notifier::watch_expiry;
use crate::settings::Settings;

mod db;
pub mod certs;
mod settings;
pub mod data;
mod helper;
mod auth;
pub mod constants;
mod api;
mod metrics;
mod notification;
mod acme;
mod acme_client;
pub(crate) mod dns_check;

type ApiError = data::error::ApiError;

#[get("/")]
fn scalar_ui() -> RawHtml<String> {
    let config = serde_json::json!({
        "url": "/api/openapi.json",
        "theme": "bluePlanet",
        "hideDarkModeToggle": true,
        "persistAuth": true,
        "agent": { "disabled": true }
    });
    RawHtml(scalar_api_reference::scalar_html(&config, Some("/api/scalar.js")))
}

#[get("/scalar.js")]
fn scalar_js() -> Option<(ContentType, Vec<u8>)> {
    let (mime, content) = scalar_api_reference::get_asset_with_mime("scalar.js")?;
    let ct = ContentType::parse_flexible(&mime).unwrap_or(ContentType::JavaScript);
    Some((ct, content))
}

pub async fn create_rocket() -> Rocket<Build> {
    // instant-acme's HTTP client uses rustls ClientConfig::builder(), which needs a
    // process-wide CryptoProvider when multiple rustls backends are compiled in
    // (aws-lc-rs + ring both present). Install aws-lc-rs as the default once.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut filter = EnvFilter::try_from_default_env().unwrap_or_default();


    filter = if let Ok(env_var) = env::var("VAULTLS_LOG_LEVEL") {
        match env_var.as_str() {
            "trace" => {
                filter.add_directive("vaultls=trace".parse().unwrap())
                      .add_directive("rocket=trace".parse().unwrap())
            },
            "debug" => {
                filter.add_directive("vaultls=debug".parse().unwrap())
                      .add_directive("rocket=debug".parse().unwrap())
            },
            "info" => {
                filter.add_directive("vaultls=info".parse().unwrap())
                      .add_directive("rocket=info".parse().unwrap())
            },
            "warn" => filter.add_directive("vaultls=warn".parse().unwrap()),
            "error" => filter.add_directive("vaultls=error".parse().unwrap()),
            _ => filter.add_directive("vaultls=info".parse().unwrap())
        }
    } else { filter.add_directive("vaultls=info".parse().unwrap()) };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    info!("Starting mTLS Certificates API");
    info!("Version {VAULTLS_VERSION}");

    info!("Loading settings from file");
    let settings = Settings::load_from_file(None).expect("Failed loading settings");
    trace!("Settings loaded: {:?}", settings);

    let db_path = Path::new(DB_FILE_PATH);
    let db_initialized = db_path.exists();
    let mut encrypted = settings.get_db_encrypted();

    if !encrypted && let Ok(db_secret) = get_secret("VAULTLS_DB_SECRET") {
        if db_initialized {
            VaulTLSDB::migrate_to_encrypted(&db_secret).expect("Failed to migrate database to encrypted");
        }
        settings.set_db_encrypted().expect("Failed to set database to encrypted in settings");
        encrypted = true;
    }

    let db = VaulTLSDB::new(encrypted, false).expect("Failed opening SQLite database");
    db.fix_password().await.expect("Failed fixing passwords");
    db.backfill_serials().await.expect("Failed backfilling certificate serials");
    if !db_initialized {
        info!("New database. Set initial database file permissions to 0600");
        // Adjust permissions
        let mut perms = fs::metadata(db_path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(db_path, perms).unwrap();
    }
    info!("Database initialized");

    if let Ok(email) = env::var("VAULTLS_ACCOUNT_EMAIL") && let Ok(password) = get_secret("VAULTLS_ACCOUNT_PASSWORD") {
        info!("Setting password for user {} and exiting", email);
        let user = db.get_user_by_email(email.clone()).await.expect("Failed to find user");
        let password_hash = Password::new_double_hash(&password).expect("Failed to hash password");
        db.set_user_password(user.id, password_hash).await.expect("Failed to set password");
        info!("Password for user {} successfully set. Exiting.", email);
        std::process::exit(0);
    }

    let oidc_settings = settings.get_oidc();
    let oidc = match oidc_settings.auth_url.is_empty() {
        true => None,
        false => {
            debug!("OIDC enabled. Trying to connect to {}.", oidc_settings.auth_url);
            OidcAuth::new(&oidc_settings).await.ok()
        }
    };

    match oidc.is_some() {
        true => info!("OIDC is active."),
        false => info!("OIDC is inactive.")
    }

    let mail_settings = settings.get_mail();
    let mailer = match mail_settings.is_valid() {
        true => {
            debug!("Mail enabled. Trying to connect to {}.", mail_settings.smtp_host);
            Mailer::new(&mail_settings, &settings.get_vaultls_url()).await.ok()
        },
        false => None
    };

    match mailer.is_some() {
        true => info!("Mail notifications are active."),
        false => info!("Mail notifications are inactive.")
    }

    match settings.get_acme_enabled() {
        true => info!("ACME is active."),
        false => info!("ACME is inactive.")
    }

    // Migrate certs
    migrate_ca_storage().expect("Failed migrating CA storage paths");

    let rocket_secret = get_secret("VAULTLS_API_SECRET").expect("Failed to get VAULTLS_API_SECRET");
    trace!("Rocket secret: {}", rocket_secret);
    
    let mailer = Arc::new(Mutex::new(mailer));

    let app_state = AppState {
        db: db.clone(),
        settings,
        oidc: Arc::new(Mutex::new(oidc)),
        mailer: mailer.clone()
    };

    let watcher_settings = app_state.settings.clone();
    tokio::spawn(async move {
        watch_expiry(db.clone(), mailer.clone(), watcher_settings).await;
    });

    trace!("App State: {:?}", app_state);

    info!("Initialization complete.");

    let figment = Config::figment()
        .merge(("secret_key", rocket_secret))
        .merge(("port", API_PORT));

    rocket::build()
        .configure(figment)
        .manage(app_state)
        .mount(
            "/api",
            openapi_get_routes![
                version,
                get_certificates,
                create_ca,
                import_ca,
                import_certificate,
                create_user_certificate,
                get_all_ca,
                download_current_tls_ca,
                download_ca_bundle,
                download_current_ssh_ca,
                download_ca,
                download_ca_fullchain,
                download_certificate,
                delete_user_cert,
                revoke_certificate,
                download_crl,
                validate_certificate,
                delete_ca,
                fetch_certificate_password,
                fetch_settings,
                update_settings,
                is_setup,
                setup,
                login,
                change_password,
                logout,
                oidc_login,
                oidc_callback,
                get_current_user,
                get_users,
                create_user,
                delete_user,
                update_user,
                get_acme_orders,
                get_acme_accounts,
                create_acme_account,
                update_acme_account,
                delete_acme_account,
                service_token,
                create_service_account,
                list_service_accounts,
                revoke_service_account,
                delete_service_account,
                get_acme_client_providers,
                create_acme_client_provider,
                delete_acme_client_provider,
                update_acme_client_provider,
                get_acme_client_orders,
                create_acme_client_order,
                issue_acme_client_order,
                check_acme_client_order_dns,
                delete_acme_client_order
            ],
        )
        .mount("/api/acme", acme::protocol_routes())
        .attach(acme::NonceFairing)
        .mount("/api", routes![scalar_ui, scalar_js])
        .mount("/", routes![crate::metrics::metrics])
        .attach(AdHoc::config::<Settings>())
}

pub async fn create_test_rocket() -> Rocket<Build> {
    let db = VaulTLSDB::new(false, true).expect("Failed opening SQLite database");
    let settings = Settings::default();
    let oidc = None;

    let mail_settings = settings.get_mail();
    let mailer = match mail_settings.is_valid() {
        true => {
            Mailer::new(&mail_settings, &settings.get_vaultls_url()).await.ok()
        },
        false => None
    };

    let app_state = AppState {
        db,
        settings,
        oidc: Arc::new(Mutex::new(oidc)),
        mailer: Arc::new(Mutex::new(mailer))
    };


    rocket::build()
        .manage(app_state)
        .mount(
            "/",
            openapi_get_routes![
                version,
                get_certificates,
                create_user_certificate,
                create_ca,
                import_ca,
                import_certificate,
                get_all_ca,
                download_current_tls_ca,
                download_ca_bundle,
                download_current_ssh_ca,
                download_ca,
                download_ca_fullchain,
                download_certificate,
                delete_user_cert,
                revoke_certificate,
                download_crl,
                validate_certificate,
                delete_ca,
                fetch_certificate_password,
                fetch_settings,
                update_settings,
                is_setup,
                setup,
                login,
                change_password,
                logout,
                oidc_login,
                oidc_callback,
                get_current_user,
                get_users,
                create_user,
                delete_user,
                update_user,
                service_token,
                create_service_account,
                list_service_accounts,
                revoke_service_account,
                delete_service_account,
                get_acme_client_providers,
                create_acme_client_provider,
                delete_acme_client_provider,
                update_acme_client_provider,
                get_acme_client_orders,
                create_acme_client_order,
                issue_acme_client_order,
                check_acme_client_order_dns,
                delete_acme_client_order
            ],
        )
        .mount(
            "/api",
            openapi_get_routes![
                version,
                get_certificates,
                create_user_certificate,
                create_ca,
                import_ca,
                import_certificate,
                get_all_ca,
                download_current_tls_ca,
                download_ca_bundle,
                download_current_ssh_ca,
                download_ca,
                download_ca_fullchain,
                download_certificate,
                delete_user_cert,
                revoke_certificate,
                download_crl,
                validate_certificate,
                delete_ca,
                fetch_certificate_password,
                fetch_settings,
                update_settings,
                is_setup,
                setup,
                login,
                change_password,
                logout,
                oidc_login,
                oidc_callback,
                get_current_user,
                get_users,
                create_user,
                delete_user,
                update_user,
                service_token,
                create_service_account,
                list_service_accounts,
                revoke_service_account,
                delete_service_account,
                get_acme_client_providers,
                create_acme_client_provider,
                delete_acme_client_provider,
                update_acme_client_provider,
                get_acme_client_orders,
                create_acme_client_order,
                issue_acme_client_order,
                check_acme_client_order_dns,
                delete_acme_client_order
            ],
        )
        .mount("/api", routes![scalar_ui, scalar_js])
        .mount("/", routes![crate::metrics::metrics])
}

#[cfg(test)]
mod tests {
    /// Verify the rustls CryptoProvider install is idempotent and leaves
    /// a default installed. Called in a single-threaded context so there is
    /// no cross-test flakiness — install_default() is a no-op if already set.
    #[test]
    fn rustls_crypto_provider_installs() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "rustls default CryptoProvider should be set after install_default()"
        );
    }
}