//! Prometheus text-exposition metrics, computed on scrape.
//!
//! Not yet wired to an HTTP route or DB queries (see follow-up tasks), so the
//! public surface is intentionally unused for now.
#![allow(dead_code)]

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
}
