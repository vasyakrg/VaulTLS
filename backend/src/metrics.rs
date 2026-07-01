//! Prometheus text-exposition metrics, computed on scrape.

use rocket::{get, State};
use rocket::http::ContentType;
use crate::data::objects::AppState;
use crate::data::enums::{CertificateType, CAType};

pub(crate) struct CertMetric {
    pub id: i64,
    pub cn: String,
    pub cert_type: &'static str,
    pub issuer: String,
    pub expiry_seconds: i64,
    pub revoked: bool,
}

pub(crate) struct CaMetric {
    pub id: i64,
    pub cn: String,
    pub ca_type: &'static str,
    pub expiry_seconds: i64,
}

pub(crate) struct AcmeOrderMetric {
    pub id: i64,
    pub domain: String,
    pub status: String,
    pub created_seconds: i64,
}

fn escape_label_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Render the full exposition body. Deterministic ordering (input order preserved).
pub(crate) fn render_metrics(
    version: &str,
    certs: &[CertMetric],
    cas: &[CaMetric],
    orders: &[AcmeOrderMetric],
) -> String {
    use std::collections::BTreeMap;
    use std::fmt::Write;
    let mut s = String::new();

    // build_info
    let _ = writeln!(s, "# HELP vaultls_build_info VaulTLS build information.");
    let _ = writeln!(s, "# TYPE vaultls_build_info gauge");
    let _ = writeln!(s, "vaultls_build_info{{version=\"{}\"}} 1", escape_label_value(version));

    // certificate expiry (non-revoked only)
    let _ = writeln!(s, "# HELP vaultls_certificate_expiry_timestamp_seconds Leaf certificate notAfter as unix seconds.");
    let _ = writeln!(s, "# TYPE vaultls_certificate_expiry_timestamp_seconds gauge");
    for c in certs.iter().filter(|c| !c.revoked) {
        let _ = writeln!(
            s,
            "vaultls_certificate_expiry_timestamp_seconds{{id=\"{}\",cn=\"{}\",type=\"{}\",issuer=\"{}\"}} {}",
            c.id, escape_label_value(&c.cn), c.cert_type, escape_label_value(&c.issuer), c.expiry_seconds
        );
    }

    // certificates_total{type}
    let mut by_type: BTreeMap<&'static str, i64> = BTreeMap::new();
    for c in certs {
        *by_type.entry(c.cert_type).or_insert(0) += 1;
    }
    let _ = writeln!(s, "# HELP vaultls_certificates_total Total certificates by type.");
    let _ = writeln!(s, "# TYPE vaultls_certificates_total gauge");
    for (t, n) in &by_type {
        let _ = writeln!(s, "vaultls_certificates_total{{type=\"{t}\"}} {n}");
    }

    // expired / revoked aggregates
    let now = crate::helper::now_seconds();
    let expired = certs.iter().filter(|c| !c.revoked && c.expiry_seconds < now).count();
    let revoked = certs.iter().filter(|c| c.revoked).count();
    let _ = writeln!(s, "# HELP vaultls_certificates_expired_total Non-revoked certificates already expired.");
    let _ = writeln!(s, "# TYPE vaultls_certificates_expired_total gauge");
    let _ = writeln!(s, "vaultls_certificates_expired_total {expired}");
    let _ = writeln!(s, "# HELP vaultls_certificates_revoked_total Revoked certificates.");
    let _ = writeln!(s, "# TYPE vaultls_certificates_revoked_total gauge");
    let _ = writeln!(s, "vaultls_certificates_revoked_total {revoked}");

    // CA expiry
    let _ = writeln!(s, "# HELP vaultls_ca_expiry_timestamp_seconds CA certificate notAfter as unix seconds.");
    let _ = writeln!(s, "# TYPE vaultls_ca_expiry_timestamp_seconds gauge");
    for c in cas {
        let _ = writeln!(
            s,
            "vaultls_ca_expiry_timestamp_seconds{{id=\"{}\",cn=\"{}\",type=\"{}\"}} {}",
            c.id, escape_label_value(&c.cn), c.ca_type, c.expiry_seconds
        );
    }

    // ACME order problems (non-valid only)
    let _ = writeln!(s, "# HELP vaultls_acme_order_created_timestamp_seconds Creation time of in-flight/failed ACME orders as unix seconds.");
    let _ = writeln!(s, "# TYPE vaultls_acme_order_created_timestamp_seconds gauge");
    for o in orders.iter().filter(|o| o.status != "valid") {
        let _ = writeln!(
            s,
            "vaultls_acme_order_created_timestamp_seconds{{id=\"{}\",domain=\"{}\",status=\"{}\"}} {}",
            o.id, escape_label_value(&o.domain), escape_label_value(&o.status), o.created_seconds
        );
    }

    // acme_orders_total{status}
    let mut by_status: BTreeMap<String, i64> = BTreeMap::new();
    for o in orders {
        *by_status.entry(o.status.clone()).or_insert(0) += 1;
    }
    let _ = writeln!(s, "# HELP vaultls_acme_orders_total ACME client orders by status.");
    let _ = writeln!(s, "# TYPE vaultls_acme_orders_total gauge");
    for (st, n) in &by_status {
        let _ = writeln!(s, "vaultls_acme_orders_total{{status=\"{}\"}} {n}", escape_label_value(st));
    }

    s
}

use rocket::request::{FromRequest, Outcome, Request};
use rocket::http::Status;

/// Pure token gate. `configured` = trimmed env value (None or empty = open).
fn check_metrics_token(configured: Option<&str>, auth_header: Option<&str>) -> bool {
    match configured {
        None => true,
        Some(t) if t.is_empty() => true,
        Some(t) => auth_header
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|got| got == t)
            .unwrap_or(false),
    }
}

pub(crate) struct MetricsAuth;

fn cert_type_str(t: CertificateType) -> &'static str {
    match t {
        CertificateType::TLSClient => "tls_client",
        CertificateType::TLSServer => "tls_server",
        CertificateType::SSHClient => "ssh_client",
        CertificateType::SSHServer => "ssh_server",
    }
}

fn ca_type_str(t: CAType) -> &'static str {
    match t {
        CAType::TLS => "tls",
        CAType::SSH => "ssh",
    }
}

#[get("/metrics")]
pub(crate) async fn metrics(state: &State<AppState>, _auth: MetricsAuth) -> Result<(ContentType, String), rocket::http::Status> {
    let certs_db = state.db.get_user_certs(None, None, None).await
        .map_err(|_| rocket::http::Status::InternalServerError)?;
    let cas_db = state.db.get_all_ca().await
        .map_err(|_| rocket::http::Status::InternalServerError)?;
    let orders_db = state.db.get_all_acme_client_orders().await
        .map_err(|_| rocket::http::Status::InternalServerError)?;
    let providers = state.db.get_all_acme_client_providers().await
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    // issuer lookups
    let provider_name = |pid: i64| providers.iter().find(|p| p.id == pid).map(|p| p.name.clone());
    let ca_cn = |cid: i64| cas_db.iter().find(|c| c.id == cid).map(|c| c.name.cn.clone());

    let certs: Vec<CertMetric> = certs_db.iter().map(|c| {
        let issuer = if let Some(pid) = c.acme_provider_id {
            format!("acme:{}", provider_name(pid).unwrap_or_else(|| pid.to_string()))
        } else if let Some(cid) = c.ca_id {
            format!("ca:{}", ca_cn(cid).unwrap_or_else(|| cid.to_string()))
        } else {
            "imported".to_string()
        };
        CertMetric {
            id: c.id,
            cn: c.name.cn.clone(),
            cert_type: cert_type_str(c.certificate_type),
            issuer,
            expiry_seconds: c.valid_until / 1000,
            revoked: c.revoked_at.is_some(),
        }
    }).collect();

    let cas: Vec<CaMetric> = cas_db.iter().map(|c| CaMetric {
        id: c.id,
        cn: c.name.cn.clone(),
        ca_type: ca_type_str(c.ca_type),
        expiry_seconds: c.valid_until / 1000,
    }).collect();

    let orders: Vec<AcmeOrderMetric> = orders_db.iter().map(|o| AcmeOrderMetric {
        id: o.id,
        domain: o.domain.clone(),
        status: o.status.clone(),
        created_seconds: o.created_on / 1000,
    }).collect();

    let body = render_metrics(crate::constants::VAULTLS_VERSION, &certs, &cas, &orders);
    Ok((ContentType::new("text", "plain").with_params(("version", "0.0.4")), body))
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for MetricsAuth {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let configured = std::env::var("VAULTLS_METRICS_TOKEN").ok();
        let configured_trimmed = configured.as_deref().map(str::trim);
        let header = req.headers().get_one("Authorization");
        if check_metrics_token(configured_trimmed, header) {
            Outcome::Success(MetricsAuth)
        } else {
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_label_values() {
        assert_eq!(escape_label_value(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape_label_value("line1\nline2"), r"line1\nline2");
        assert_eq!(escape_label_value("plain"), "plain");
    }

    #[test]
    fn renders_build_info_and_cert() {
        let certs = vec![CertMetric {
            id: 7,
            cn: "novotelecom.ru".into(),
            cert_type: "tls_server",
            issuer: "acme:Let's Encrypt".into(),
            expiry_seconds: 1_730_419_200,
            revoked: false,
        }];
        let out = render_metrics("v1.2.3", &certs, &[], &[]);
        assert!(out.contains("# TYPE vaultls_build_info gauge"));
        assert!(out.contains(r#"vaultls_build_info{version="v1.2.3"} 1"#));
        assert!(out.contains(
            r#"vaultls_certificate_expiry_timestamp_seconds{id="7",cn="novotelecom.ru",type="tls_server",issuer="acme:Let's Encrypt"} 1730419200"#
        ));
        // aggregate present
        assert!(out.contains(r#"vaultls_certificates_total{type="tls_server"} 1"#));
    }

    #[test]
    fn revoked_excluded_from_expiry_but_counted() {
        let certs = vec![CertMetric {
            id: 1, cn: "r".into(), cert_type: "tls_client", issuer: "imported".into(),
            expiry_seconds: 100, revoked: true,
        }];
        let out = render_metrics("v0", &certs, &[], &[]);
        assert!(!out.contains("vaultls_certificate_expiry_timestamp_seconds{id=\"1\""));
        assert!(out.contains("vaultls_certificates_revoked_total 1"));
    }

    #[test]
    fn token_check_logic() {
        // unset/empty → always allow
        assert!(check_metrics_token(None, None));
        assert!(check_metrics_token(Some(""), Some("anything")));
        // set → require exact bearer
        assert!(check_metrics_token(Some("secret"), Some("Bearer secret")));
        assert!(!check_metrics_token(Some("secret"), Some("Bearer wrong")));
        assert!(!check_metrics_token(Some("secret"), None));
        assert!(!check_metrics_token(Some("secret"), Some("secret"))); // missing "Bearer "
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_exposition() {
        // No VAULTLS_METRICS_TOKEN set in test → open endpoint.
        let rocket = crate::create_test_rocket().await;
        let client = rocket::local::asynchronous::Client::tracked(rocket).await.unwrap();
        let resp = client.get("/metrics").dispatch().await;
        assert_eq!(resp.status(), rocket::http::Status::Ok);
        let body = resp.into_string().await.unwrap();
        assert!(body.contains("vaultls_build_info"));
        assert!(body.contains("# TYPE vaultls_certificates_total gauge"));
    }
}
