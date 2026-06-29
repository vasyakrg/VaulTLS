use std::net::SocketAddr;
use hickory_resolver::config::ConnectionConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::Record;
use tracing::{error, debug};

pub(crate) fn challenge_record_name(domain: &str) -> String {
    format!("_acme-challenge.{}.", domain.trim_end_matches('.'))
}

/// Checks that among TXT records for `_acme-challenge.<domain>`, `expected_value` is present.
/// `resolver_addr = None` → system resolver; `Some("")` also → system resolver;
/// `Some("IP:port")` or `Some("IP")` → UDP resolver at that address.
pub(crate) async fn txt_record_present(
    domain: &str,
    expected_value: &str,
    resolver_addr: Option<&str>,
) -> bool {
    let name = challenge_record_name(domain);

    let resolver = match build_plain_resolver(resolver_addr.unwrap_or("")) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to build DNS resolver: {e}");
            return false;
        }
    };

    match resolver.txt_lookup(&name).await {
        Ok(records) => {
            let matched = records.answers().iter().any(|txt: &Record| {
                let record_text: String = txt.data.to_string();
                record_text == expected_value
            });
            if !matched {
                debug!(domain = domain, expected = expected_value, "TXT not yet visible");
            }
            matched
        }
        Err(e) => {
            debug!(domain = domain, error = %e, "TXT lookup failed");
            false
        }
    }
}

/// Build a plain UDP resolver. Empty addr → system resolver.
/// Copied verbatim from `acme/routes.rs::build_udp_resolver`.
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
