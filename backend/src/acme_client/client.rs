use anyhow::{anyhow, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, ExternalAccountKey, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, RetryPolicy,
};

use crate::acme_client::types::{AcmeClientProvider, TxtRecord};

pub(crate) struct CreatedOrder {
    pub order_url: String,
    pub txt_records: Vec<TxtRecord>,
    /// Serialised `AccountCredentials` JSON, present ONLY when a new account was just registered.
    /// `None` when restored from existing credentials (caller should NOT overwrite stored creds).
    pub account_credentials: Option<String>,
    pub expires_at: Option<i64>,
}

/// Restore an existing ACME account from stored credentials, or register a new one.
///
/// Returns `(account, Some(creds_json))` if a new account was created — the caller must persist
/// this JSON. Returns `(account, None)` if the account was restored from existing credentials.
async fn account_for(provider: &AcmeClientProvider) -> Result<(Account, Option<String>)> {
    // Account::builder() uses the DefaultClient (hyper + rustls, platform trust store).
    // It takes no arguments; the crypto backend is selected at compile time via the
    // "aws-lc-rs" / "ring" feature flags of instant-acme.
    let builder = Account::builder().map_err(|e| anyhow!("ACME builder init failed: {e}"))?;

    if let Some(creds_json) = &provider.account_credentials {
        let creds: AccountCredentials = serde_json::from_str(creds_json)
            .map_err(|e| anyhow!("invalid stored account credentials: {e}"))?;
        let account = builder
            .from_credentials(creds)
            .await
            .map_err(|e| anyhow!("failed to restore ACME account: {e}"))?;
        return Ok((account, None));
    }

    // First-time registration
    let contact = format!("mailto:{}", provider.account_email);
    let new_account = NewAccount {
        contact: &[contact.as_str()],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    // EAB (External Account Binding) — required for ZeroSSL, optional for LE
    // `eab_hmac_key` is stored as raw bytes; ExternalAccountKey::new() takes &[u8] directly.
    let eab = match (&provider.eab_kid, &provider.eab_hmac_key) {
        (Some(kid), Some(key_bytes)) => {
            Some(ExternalAccountKey::new(kid.clone(), key_bytes.as_slice()))
        }
        _ => None,
    };

    let (account, creds) = builder
        .create(&new_account, provider.directory_url.clone(), eab.as_ref())
        .await
        .map_err(|e| anyhow!("failed to register ACME account: {e}"))?;

    let creds_json =
        serde_json::to_string(&creds).map_err(|e| anyhow!("failed to serialise credentials: {e}"))?;
    Ok((account, Some(creds_json)))
}

/// Phase 1 of the manual dns-01 flow: register/restore the ACME account, create an order, and
/// collect the TXT challenge values.
///
/// **Does NOT call `set_ready`** — the caller must add the returned TXT records to DNS and then
/// invoke phase 2 (Task 9) to finalise the order.
pub(crate) async fn create_order(
    provider: &AcmeClientProvider,
    domain: &str,
    include_wildcard: bool,
) -> Result<CreatedOrder> {
    let (account, new_creds) = account_for(provider).await?;

    let ids: Vec<Identifier> = order_identifiers(domain, include_wildcard)
        .into_iter()
        .map(Identifier::Dns)
        .collect();

    let mut order = account
        .new_order(&NewOrder::new(&ids))
        .await
        .map_err(|e| anyhow!("failed to create ACME order: {e}"))?;

    let order_url = order.url().to_string();

    // Base domain name used for the _acme-challenge TXT record.
    // Both bare-domain and wildcard authorisations map to the same TXT name but produce
    // different digest values — both values must be published before calling set_ready.
    let base_domain = domain.trim_end_matches('.');

    let mut txt_records = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| anyhow!("failed to fetch authorization: {e}"))?;
        let challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("dns-01 challenge not offered for this authorization"))?;
        // key_authorization() returns KeyAuthorization (owned), not Result — no ? needed.
        let value = challenge.key_authorization().dns_value();
        txt_records.push(TxtRecord {
            name: format!("_acme-challenge.{base_domain}"),
            value,
        });
        // set_ready is intentionally NOT called here (phase 2 handles that after DNS propagation).
    }

    Ok(CreatedOrder {
        order_url,
        txt_records,
        account_credentials: new_creds,
        expires_at: None,
    })
}

pub(crate) struct IssuedCert {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

pub(crate) struct PackedCert {
    pub pkcs12_der: Vec<u8>,
    /// Unix milliseconds from the leaf certificate's notAfter.
    pub valid_until: i64,
}

pub(crate) fn pack_issued_certificate(
    certificate_pem: &str,
    private_key_pem: &str,
    password: &str,
) -> Result<PackedCert> {
    use crate::certs::import::{parse_pem_bundle, parse_private_key};
    use openssl::asn1::Asn1Time;

    let mut certs = parse_pem_bundle(certificate_pem.as_bytes())?;
    if certs.is_empty() {
        return Err(anyhow!("certificate PEM bundle is empty"));
    }
    let leaf = certs.remove(0);
    let chain = certs; // remaining certs form the CA chain

    let key = parse_private_key(private_key_pem.as_bytes())?;

    let mut ca_stack = openssl::stack::Stack::new()?;
    for c in &chain {
        ca_stack.push(c.clone())?;
    }
    let p12 = openssl::pkcs12::Pkcs12::builder()
        .name("letsencrypt")
        .ca(ca_stack)
        .cert(&leaf)
        .pkey(&key)
        .build2(password)?;
    let pkcs12_der = p12.to_der()?;

    let epoch = Asn1Time::from_unix(0)?;
    let diff = epoch.diff(leaf.not_after())?;
    let valid_until = ((diff.days as i64) * 86_400 + diff.secs as i64) * 1_000;

    Ok(PackedCert { pkcs12_der, valid_until })
}

/// Phase 2 of the manual dns-01 flow: verify TXT records are visible, signal readiness to the
/// ACME server, wait for validation, finalise the order, and return the issued certificate.
///
/// **Precheck before set_ready** — if any TXT record is not yet resolvable, the function returns
/// `Err` immediately without contacting the ACME server, preserving rate-limits.
pub(crate) async fn issue_order(
    provider: &AcmeClientProvider,
    order_url: &str,
    domain: &str,
    txt_records: &[TxtRecord],
    resolver_addr: &str,
    accept_invalid_certs: bool,
) -> Result<IssuedCert> {
    // 1. DNS precheck — every TXT record must be visible before we tell the ACME server anything.
    //    Uses the admin-configured resolver (VAULTLS_ACME_DNS_RESOLVER) so the pre-check queries the
    //    same nameserver as the ACME server-side validation, not the container's system resolver.
    //    Defense-in-depth: the frontend already gates on a successful check, but never trust it.
    let precheck = check_txt_records(domain, txt_records, resolver_addr, accept_invalid_certs).await?;
    if !precheck.ok {
        let expected_block = precheck
            .expected
            .iter()
            .map(|v| format!("  • {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let found_block = if precheck.found.is_empty() {
            "  (none — no TXT records published at this name)".to_string()
        } else {
            precheck.found.iter().map(|v| format!("  • {v}")).collect::<Vec<_>>().join("\n")
        };
        return Err(anyhow!(
            "TXT records for _acme-challenge.{domain} are not visible in DNS yet.\n\
             Expected:\n{expected_block}\n\
             Currently published:\n{found_block}\n\
             Add the missing records to your bind9 zone, bump the serial, run rndc reload, then retry."
        ));
    }

    // 2. Restore account and order.
    let (account, _) = account_for(provider).await?;
    let mut order = account
        .order(order_url.to_string())
        .await
        .map_err(|e| anyhow!("failed to fetch ACME order: {e}"))?;

    // An order that already failed validation on a previous attempt is permanently `invalid`.
    // Calling set_ready again would error confusingly — surface the real reason instead and tell
    // the user to create a fresh order.
    if order.state().status == OrderStatus::Invalid {
        return Err(order_validation_error(&mut order, domain, OrderStatus::Invalid).await);
    }

    // 3. set_ready on each dns-01 challenge.
    //    Authorizations<'_> borrows `order` mutably; drop it before calling poll_ready.
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz =
                result.map_err(|e| anyhow!("failed to fetch authorization: {e}"))?;
            if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
                challenge
                    .set_ready()
                    .await
                    .map_err(|e| anyhow!("set_ready failed: {e}"))?;
            }
        }
    } // authorizations dropped here — `order` is usable again

    // 4. Poll for challenge validation. `poll_ready` returns the terminal OrderStatus and does
    //    NOT error when the order goes `invalid` — the CA rejected the challenge. We must inspect
    //    the status ourselves and surface the CA's per-challenge error, otherwise the user only
    //    sees a downstream `orderNotReady` from finalize().
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|e| anyhow!("poll_ready failed: {e}"))?;

    if status != OrderStatus::Ready {
        return Err(order_validation_error(&mut order, domain, status).await);
    }

    // 5. Finalize: instant-acme generates the CSR internally and returns the private key PEM.
    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| anyhow!("order finalize failed: {e}"))?;

    // 6. Poll until the certificate chain is issued; returns PEM chain.
    let certificate_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| anyhow!("poll_certificate failed: {e}"))?;

    Ok(IssuedCert {
        certificate_pem,
        private_key_pem,
    })
}

/// Build a descriptive error when an order fails to reach `Ready`. Fetches each authorization
/// and extracts the CA-provided per-challenge `error` (RFC 8555 Problem detail) so the user sees
/// *why* the CA rejected the challenge instead of a generic `orderNotReady`.
async fn order_validation_error(order: &mut Order, domain: &str, status: OrderStatus) -> anyhow::Error {
    let mut reasons: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let authz = match result {
            Ok(a) => a,
            Err(e) => {
                reasons.push(format!("failed to fetch authorization: {e}"));
                continue;
            }
        };
        let ident = authz.identifier().to_string();
        for ch in &authz.challenges {
            if let Some(err) = &ch.error {
                let detail = err
                    .detail
                    .clone()
                    .or_else(|| err.r#type.clone())
                    .unwrap_or_else(|| "no detail provided".into());
                reasons.push(format!("{ident} [{:?}]: {detail}", ch.r#type));
            }
        }
    }

    let joined = if reasons.is_empty() {
        "the ACME server did not provide a specific reason".to_string()
    } else {
        reasons.join("; ")
    };

    anyhow!(
        "ACME server rejected validation for {domain} (order status: {status:?}).\n\
         Reason(s): {joined}.\n\
         The CA runs its OWN DNS lookup of the _acme-challenge TXT records — this failure means \
         the CA's resolver could not see them (propagation delay or a cached negative answer). \
         An order that has gone invalid cannot be revived: wait for the TXT record TTL to expire, \
         delete this order, then create a fresh one and retry."
    )
}

/// Outcome of a resolver-only TXT visibility check. `ok` is true when every expected
/// record is currently published.
pub(crate) struct DnsCheckOutcome {
    pub ok: bool,
    pub expected: Vec<String>,
    pub found: Vec<String>,
    // Not read by `issue_order` today (it recomputes the diff for display), but part of the
    // outcome's public shape for future consumers (e.g. a standalone DNS-check endpoint).
    #[allow(dead_code)]
    pub missing: Vec<String>,
}

/// Resolve the `_acme-challenge.<domain>` TXT records via the configured resolver and compare
/// them to `txt_records`. Never contacts the ACME server. Returns `Err` only if the DNS lookup
/// itself fails (network / NXDOMAIN / bad resolver address).
pub(crate) async fn check_txt_records(
    domain: &str,
    txt_records: &[TxtRecord],
    resolver_addr: &str,
    accept_invalid_certs: bool,
) -> Result<DnsCheckOutcome> {
    let found = crate::dns_check::lookup_txt_values(domain, resolver_addr, accept_invalid_certs)
        .await
        .map_err(|e| anyhow!(
            "DNS lookup for _acme-challenge.{domain} failed: {e}. Check your bind9 zone / resolver and try again."
        ))?;
    let missing = missing_txt_values(txt_records, &found);
    let expected = txt_records.iter().map(|r| r.value.clone()).collect();
    Ok(DnsCheckOutcome { ok: missing.is_empty(), expected, found, missing })
}

/// Returns the subset of `expected` TXT values that are NOT present among `found`,
/// preserving the order of `expected`. Pure comparison — no network.
pub(crate) fn missing_txt_values(expected: &[TxtRecord], found: &[String]) -> Vec<String> {
    expected
        .iter()
        .map(|r| r.value.clone())
        .filter(|v| !found.iter().any(|f| f == v))
        .collect()
}

pub(crate) fn order_identifiers(domain: &str, include_wildcard: bool) -> Vec<String> {
    let base = domain.trim().trim_end_matches('.').to_string();
    if include_wildcard {
        vec![base.clone(), format!("*.{base}")]
    } else {
        vec![base]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_domain() {
        assert_eq!(order_identifiers("example.com", false), vec!["example.com".to_string()]);
    }

    #[test]
    fn domain_with_wildcard() {
        assert_eq!(
            order_identifiers("example.com", true),
            vec!["example.com".to_string(), "*.example.com".to_string()]
        );
    }

    #[test]
    fn missing_txt_values_reports_only_absent() {
        let expected = vec![
            TxtRecord { name: "_acme-challenge.example.com".into(), value: "aaa".into() },
            TxtRecord { name: "_acme-challenge.example.com".into(), value: "bbb".into() },
        ];
        // Only "aaa" is published.
        let found = vec!["aaa".to_string(), "zzz".to_string()];
        assert_eq!(missing_txt_values(&expected, &found), vec!["bbb".to_string()]);

        // All published → nothing missing.
        let found_all = vec!["bbb".to_string(), "aaa".to_string()];
        assert!(missing_txt_values(&expected, &found_all).is_empty());

        // None published → both missing, in expected order.
        assert_eq!(
            missing_txt_values(&expected, &[]),
            vec!["aaa".to_string(), "bbb".to_string()]
        );
    }

    #[test]
    fn pack_issued_certificate_roundtrip() {
        use crate::certs::import::tests_support::self_signed_ca;
        use openssl::pkcs12::Pkcs12;

        let (x509, key) = self_signed_ca("test.example.com");
        let cert_pem = String::from_utf8(x509.to_pem().unwrap()).unwrap();
        let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();

        let packed = pack_issued_certificate(&cert_pem, &key_pem, "").unwrap();

        // PKCS#12 blob must be non-empty
        assert!(!packed.pkcs12_der.is_empty());

        // Parse back and verify the cert is present
        let parsed = Pkcs12::from_der(&packed.pkcs12_der).unwrap().parse2("").unwrap();
        assert!(parsed.cert.is_some(), "parsed PKCS#12 must contain a certificate");

        // valid_until must be in the future and within ~400 days (self_signed_ca sets 365 days)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let days_400_ms: i64 = 400 * 86_400 * 1_000;
        assert!(packed.valid_until > now_ms, "valid_until must be in the future");
        assert!(
            packed.valid_until < now_ms + days_400_ms,
            "valid_until must be within 400 days"
        );
    }
}
