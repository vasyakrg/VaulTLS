use anyhow::{anyhow, Result};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509StoreContext};

/// Parse an X.509 certificate, trying PEM first then DER.
pub fn parse_cert(bytes: &[u8]) -> Result<X509> {
    X509::from_pem(bytes).or_else(|_| X509::from_der(bytes))
        .map_err(|e| anyhow!("not a valid PEM/DER certificate: {e}"))
}

/// Parse a private key, trying PEM (PKCS#8/SEC1) then DER (PKCS#8).
pub fn parse_private_key(bytes: &[u8]) -> Result<PKey<Private>> {
    PKey::private_key_from_pem(bytes)
        .or_else(|_| PKey::private_key_from_der(bytes))
        .map_err(|e| anyhow!("not a valid PEM/DER private key: {e}"))
}

/// Parse a PKCS#12 blob into (leaf cert, optional key, chain certs).
pub fn parse_pkcs12(bytes: &[u8], password: &str) -> Result<(X509, Option<PKey<Private>>, Vec<X509>)> {
    let parsed = Pkcs12::from_der(bytes)?.parse2(password)?;
    let leaf = parsed.cert.ok_or_else(|| anyhow!("PKCS#12 has no certificate"))?;
    let chain = match parsed.ca {
        Some(stack) => stack.into_iter().collect(),
        None => Vec::new(),
    };
    Ok((leaf, parsed.pkey, chain))
}

/// Verify `leaf` is directly signed by `issuer` using a one-entry trust store.
pub fn verify_signed_by(leaf: &X509, issuer: &X509) -> bool {
    let Ok(mut builder) = X509StoreBuilder::new() else { return false };
    if builder.add_cert(issuer.clone()).is_err() { return false }
    let store = builder.build();
    let Ok(empty) = Stack::new() else { return false };
    let Ok(mut ctx) = X509StoreContext::new() else { return false };
    ctx.init(&store, leaf, &empty, |c| c.verify_cert()).unwrap_or(false)
}

/// Find the cert in `chain` that issued `leaf`: match AKI->SKI, fallback to DN.
pub fn find_issuing_ca(leaf: &X509, chain: &[X509]) -> Option<X509> {
    if let Some(aki) = leaf.authority_key_id() {
        for c in chain {
            if let Some(ski) = c.subject_key_id() {
                if ski.as_slice() == aki.as_slice() {
                    return Some(c.clone());
                }
            }
        }
    }
    // Fallback: issuer DN == candidate subject DN
    for c in chain {
        if leaf.issuer_name().try_cmp(c.subject_name()).map(|o| o.is_eq()).unwrap_or(false) {
            return Some(c.clone());
        }
    }
    None
}

/// Subject Key Identifier bytes, if present.
pub fn ski_of(cert: &X509) -> Option<Vec<u8>> {
    cert.subject_key_id().map(|s| s.as_slice().to_vec())
}

/// Split a PEM bundle into individual certificates.
pub fn parse_pem_bundle(bytes: &[u8]) -> Result<Vec<X509>> {
    let certs = X509::stack_from_pem(bytes)?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates in PEM bundle"));
    }
    Ok(certs)
}

#[cfg(test)]
pub(crate) mod tests_support {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509, X509Builder, X509NameBuilder};
    use openssl::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;

    pub fn keypair() -> PKey<Private> {
        let g = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&g).unwrap()).unwrap()
    }

    /// Build a self-signed CA cert with given CN. Returns (cert, key).
    pub fn self_signed_ca(cn: &str) -> (X509, PKey<Private>) {
        let key = keypair();
        let mut nb = X509NameBuilder::new().unwrap();
        nb.append_entry_by_text("CN", cn).unwrap();
        let name = nb.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        // Add SKI so that leaf certs can reference it via AKI
        let ski = SubjectKeyIdentifier::new().build(&b.x509v3_context(None, None)).unwrap();
        b.append_extension(ski).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    /// Build a self-signed CA cert and return it as DER bytes.
    pub fn self_signed_ca_der(cn: &str) -> Vec<u8> {
        let (cert, _) = self_signed_ca(cn);
        cert.to_der().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests_support::{keypair, self_signed_ca};
    use openssl::x509::extension::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
    use openssl::hash::MessageDigest;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;

    #[test]
    fn parse_cert_accepts_pem_and_der() {
        let (cert, _) = self_signed_ca("Root");
        let pem = cert.to_pem().unwrap();
        let der = cert.to_der().unwrap();
        assert!(parse_cert(&pem).is_ok());
        assert!(parse_cert(&der).is_ok());
    }

    #[test]
    fn parse_private_key_accepts_pem_and_der() {
        let key = keypair();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        let der = key.private_key_to_der().unwrap();
        assert!(parse_private_key(&pem).is_ok());
        assert!(parse_private_key(&der).is_ok());
    }

    #[test]
    fn parse_pem_bundle_splits_multiple_blocks() {
        let (a, _) = self_signed_ca("A");
        let (b, _) = self_signed_ca("B");
        let mut bundle = a.to_pem().unwrap();
        bundle.extend_from_slice(&b.to_pem().unwrap());
        let parsed = parse_pem_bundle(&bundle).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    /// Issue a leaf signed by `ca`, copying AKI from the CA.
    fn leaf_signed_by(cn: &str, ca: &X509, ca_key: &PKey<Private>) -> (X509, PKey<Private>) {
        let key = keypair();
        let mut nb = X509NameBuilder::new().unwrap();
        nb.append_entry_by_text("CN", cn).unwrap();
        let name = nb.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(ca.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(90).unwrap()).unwrap();
        let ski = SubjectKeyIdentifier::new().build(&b.x509v3_context(Some(ca), None)).unwrap();
        b.append_extension(ski).unwrap();
        let aki = AuthorityKeyIdentifier::new().keyid(true).build(&b.x509v3_context(Some(ca), None)).unwrap();
        b.append_extension(aki).unwrap();
        b.sign(ca_key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    #[test]
    fn verify_signed_by_accepts_correct_issuer_and_rejects_wrong() {
        let (ca, ca_key) = self_signed_ca("Real CA");
        let (other, _) = self_signed_ca("Other CA");
        let (leaf, _) = leaf_signed_by("leaf.example.com", &ca, &ca_key);
        assert!(verify_signed_by(&leaf, &ca));
        assert!(!verify_signed_by(&leaf, &other));
    }

    #[test]
    fn find_issuing_ca_locates_signer_in_chain() {
        let (ca, ca_key) = self_signed_ca("Issuing CA");
        let (leaf, _) = leaf_signed_by("leaf", &ca, &ca_key);
        let found = find_issuing_ca(&leaf, &[ca.clone()]).expect("issuer found");
        assert_eq!(found.subject_name().try_cmp(ca.subject_name()).unwrap(), std::cmp::Ordering::Equal);
    }
}
