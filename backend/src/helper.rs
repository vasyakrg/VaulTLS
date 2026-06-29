use std::{env, fs};
use std::path::Path;
use serde::Serializer;
use crate::auth::password_auth::Password;

/// Serializes a Password to a boolean
pub fn serialize_password_hash<S>(password_hash: &Option<Password>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bool(password_hash.is_some())
}

/// Serializes a private-key byte buffer as a boolean (true when a key is present).
pub fn serialize_has_private_key<S>(key: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bool(!key.is_empty())
}

/// Get secret
pub fn get_secret(name: &str) -> anyhow::Result<String> {
    if let Ok(env_var) = env::var(name) {
        Ok(if Path::new(&env_var).exists() {
            fs::read_to_string(env_var)
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            env_var
        })
    } else {
        Ok(fs::read_to_string("/run/secrets/".to_string() + name)?)
    }

}