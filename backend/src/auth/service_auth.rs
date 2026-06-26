use crate::constants::ARGON2;
use crate::ApiError;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{PasswordHasher, PasswordVerifier};
use uuid::Uuid;

/// Argon2-hash a service-account secret for storage.
pub(crate) fn hash_secret(secret: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(ARGON2
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|_| ApiError::Other("Failed to hash secret".to_string()))?
        .serialize()
        .to_string())
}

/// Verify a presented secret against a stored hash.
pub(crate) fn verify_secret(secret: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => ARGON2.verify_password(secret.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Generate a public client_id and a high-entropy secret (256 bits via two UUIDv4).
pub(crate) fn generate_credentials() -> (String, String) {
    let client_id = format!("svc_{}", Uuid::new_v4().simple());
    let secret = format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    (client_id, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrips() {
        let (_cid, secret) = generate_credentials();
        let hash = hash_secret(&secret).unwrap();
        assert!(verify_secret(&secret, &hash));
        assert!(!verify_secret("wrong-secret", &hash));
    }

    #[test]
    fn credentials_have_expected_shape() {
        let (cid, secret) = generate_credentials();
        assert!(cid.starts_with("svc_"));
        assert_eq!(secret.len(), 64); // two 32-char simple UUIDs
    }
}
