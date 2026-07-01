use std::net::SocketAddr;
use std::sync::Arc;
use hickory_resolver::config::ConnectionConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::Record;
use tracing::debug;

pub(crate) fn challenge_record_name(domain: &str) -> String {
    format!("_acme-challenge.{}.", domain.trim_end_matches('.'))
}

/// Resolve every TXT value published at `_acme-challenge.<domain>`, dispatching on the
/// resolver scheme:
/// * `https://…` → DNS-over-HTTPS
/// * `tls://…`   → DNS-over-TLS (`IP[:port][#tls-name]`)
/// * `IP[:port]` → plain UDP
/// * `""`        → system resolver
///
/// Returns the list of TXT values actually found (possibly empty), or `Err` when the
/// lookup itself failed (network error, NXDOMAIN, malformed resolver address, …).
/// This is the single lookup shared by the ACME server-side challenge validation and the
/// ACME client-side DNS pre-check, so the admin-configured resolver
/// (`VAULTLS_ACME_DNS_RESOLVER`) is honoured in both flows.
pub(crate) async fn lookup_txt_values(
    domain: &str,
    resolver_addr: &str,
    accept_invalid_certs: bool,
) -> Result<Vec<String>, String> {
    if resolver_addr.starts_with("https://") {
        return doh_txt_values(domain, resolver_addr, accept_invalid_certs).await;
    }
    if let Some(addr) = resolver_addr.strip_prefix("tls://") {
        return dot_txt_values(domain, addr).await;
    }
    udp_txt_values(domain, resolver_addr).await
}

/// Convenience wrapper: `true` when `expected_value` is among the published TXT values.
/// A failed lookup counts as "not present".
pub(crate) async fn txt_record_present_via(
    domain: &str,
    expected_value: &str,
    resolver_addr: &str,
    accept_invalid_certs: bool,
) -> bool {
    match lookup_txt_values(domain, resolver_addr, accept_invalid_certs).await {
        Ok(values) => {
            let matched = values.iter().any(|v| v == expected_value);
            if !matched {
                debug!(domain = domain, expected = expected_value, found = ?values, "TXT not yet visible");
            }
            matched
        }
        Err(e) => {
            debug!(domain = domain, error = %e, "TXT lookup failed");
            false
        }
    }
}

async fn udp_txt_values(domain: &str, addr: &str) -> Result<Vec<String>, String> {
    let resolver = build_plain_resolver(addr)?;
    let name = challenge_record_name(domain);
    match resolver.txt_lookup(&name).await {
        Ok(records) => Ok(collect_txt(records.answers())),
        Err(e) => Err(e.to_string()),
    }
}

/// DNS-over-TLS lookup. `addr` is `IP[:port][#tls-name]` (port defaults to 853;
/// omitting `#tls-name` skips certificate verification).
async fn dot_txt_values(domain: &str, addr: &str) -> Result<Vec<String>, String> {
    let resolver = build_dot_resolver(addr)?;
    let name = challenge_record_name(domain);
    match resolver.txt_lookup(&name).await {
        Ok(records) => Ok(collect_txt(records.answers())),
        Err(e) => Err(e.to_string()),
    }
}

fn collect_txt(records: &[Record]) -> Vec<String> {
    records.iter().map(|r: &Record| r.data.to_string()).collect()
}

/// DNS-over-HTTPS (RFC 8484) lookup against `url`.
async fn doh_txt_values(domain: &str, url: &str, accept_invalid_certs: bool) -> Result<Vec<String>, String> {
    use hickory_resolver::proto::op::{Message, Query};
    use hickory_resolver::proto::rr::{Name, RData, RecordType};

    let lookup_name = challenge_record_name(domain);
    let name = Name::from_ascii(&lookup_name)
        .map_err(|e| format!("Invalid DNS name for DoH query: {e}"))?;

    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::TXT);

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(query);

    let wire_bytes = message.to_vec()
        .map_err(|e| format!("Failed to encode DNS query for DoH: {e}"))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(accept_invalid_certs)
        .build()
        .map_err(|e| format!("Failed to build DoH client: {e}"))?;

    let resp = client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(wire_bytes)
        .send()
        .await
        .map_err(|e| format!("DoH request to {url} failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("DoH endpoint {url} returned status {}", resp.status()));
    }

    let bytes = resp.bytes().await
        .map_err(|e| format!("Failed to read DoH response body: {e}"))?;

    let response = Message::from_vec(&bytes)
        .map_err(|e| format!("Failed to parse DoH response: {e}"))?;

    Ok(response.answers.iter().filter_map(|record: &Record| {
        if let RData::TXT(ref txt) = record.data {
            Some(txt.to_string())
        } else {
            None
        }
    }).collect())
}

/// Build a plain UDP resolver. Empty addr → system resolver.
fn build_plain_resolver(addr: &str) -> Result<hickory_resolver::TokioResolver, String> {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::Resolver;
    use std::net::IpAddr;

    if addr.is_empty() {
        return Ok(Resolver::builder_tokio().unwrap().build().unwrap());
    }

    let socket_addr: SocketAddr = addr
        .parse()
        .or_else(|_| addr.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| format!("Invalid DNS resolver address: {addr}"))?;
    let mut connection_config = ConnectionConfig::udp();
    connection_config.port = socket_addr.port();
    let ns = NameServerConfig::new(socket_addr.ip(), false, vec![connection_config]);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
    Ok(Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .unwrap())
}

/// Build a DNS-over-TLS resolver. `addr` is `IP[:port][#tls-name]`.
fn build_dot_resolver(addr: &str) -> Result<hickory_resolver::TokioResolver, String> {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::{Resolver, TlsConfig};
    use std::net::IpAddr;

    let (addr_part, tls_name_opt) = match addr.find('#') {
        Some(idx) => (&addr[..idx], Some(addr[idx + 1..].to_string())),
        None => (addr, None),
    };

    let (ip_str, port) = if let Some(colon) = addr_part.rfind(':') {
        let port_str = &addr_part[colon + 1..];
        match port_str.parse::<u16>() {
            Ok(p) => (&addr_part[..colon], p),
            Err(_) => (addr_part, 853u16),
        }
    } else {
        (addr_part, 853u16)
    };

    let ip: IpAddr = ip_str.parse()
        .map_err(|_| format!("Invalid DoT IP address: {ip_str}"))?;
    let skip_verify = tls_name_opt.is_none();
    let tls_name = tls_name_opt.unwrap_or_else(|| ip_str.to_string());
    let mut connection_config = ConnectionConfig::tls(Arc::from(tls_name));
    connection_config.port = port;
    let ns = NameServerConfig::new(ip, false, vec![connection_config]);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    if skip_verify {
        let mut tls_cfg = TlsConfig::new()
            .map_err(|e| format!("Failed to create TLS config: {e}"))?;
        tls_cfg.insecure_skip_verify();
        builder = builder.with_tls_config(tls_cfg.config);
    }
    Ok(builder.build().unwrap())
}

#[cfg(test)]
mod tests {
    use super::challenge_record_name;

    #[test]
    fn builds_acme_challenge_name() {
        assert_eq!(
            challenge_record_name("example.com"),
            "_acme-challenge.example.com."
        );
        assert_eq!(
            challenge_record_name("sub.example.com"),
            "_acme-challenge.sub.example.com."
        );
    }
}
