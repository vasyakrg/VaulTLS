use anyhow::{anyhow, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, ExternalAccountKey, Identifier, NewAccount,
    NewOrder,
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
    use super::order_identifiers;
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
}
