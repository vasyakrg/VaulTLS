use anyhow::{anyhow, Result};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

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

/// Split a PEM bundle into individual certificates.
pub fn parse_pem_bundle(bytes: &[u8]) -> Result<Vec<X509>> {
    let certs = X509::stack_from_pem(bytes)?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates in PEM bundle"));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::hash::MessageDigest;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use openssl::x509::extension::BasicConstraints;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;

    fn keypair() -> PKey<Private> {
        let g = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&g).unwrap()).unwrap()
    }

    /// Build a self-signed CA cert with given CN. Returns (cert, key).
    fn self_signed_ca(cn: &str) -> (X509, PKey<Private>) {
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
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

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
}
