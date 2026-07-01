use rocket::serde::{Deserialize, Serialize};
use rocket_okapi::JsonSchema;

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
pub struct TxtRecord {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct AcmeClientProvider {
    pub id: i64,
    pub name: String,
    pub directory_url: String,
    pub account_email: String,
    pub eab_kid: Option<String>,
    #[serde(skip)]
    pub eab_hmac_key: Option<Vec<u8>>,
    #[serde(skip)]
    pub account_credentials: Option<String>,
    pub created_on: i64,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct AcmeClientOrder {
    pub id: i64,
    pub provider_id: i64,
    pub domain: String,
    pub include_wildcard: bool,
    pub status: String,
    pub order_url: Option<String>,
    pub txt_records: Vec<TxtRecord>,
    pub cert_id: Option<i64>,
    pub error: Option<String>,
    pub created_on: i64,
    pub expires_at: Option<i64>,
    pub renews_cert_id: Option<i64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateProviderRequest {
    pub name: String,
    pub directory_url: String,
    pub account_email: String,
    /// base64url EAB key id (для ZeroSSL/BuyPass), опционально
    pub eab_kid: Option<String>,
    /// base64url EAB HMAC key, опционально
    pub eab_hmac_key: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct UpdateProviderRequest {
    pub name: String,
    pub directory_url: String,
    pub account_email: String,
    pub eab_kid: Option<String>,
    /// base64url HMAC key; None = leave existing unchanged
    pub eab_hmac_key: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateOrderRequest {
    pub provider_id: i64,
    pub domain: String,
    pub include_wildcard: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateOrderResponse {
    pub order_id: i64,
    pub txt_records: Vec<TxtRecord>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DnsCheckResponse {
    pub ok: bool,
    pub expected: Vec<String>,
    pub found: Vec<String>,
    pub missing: Vec<String>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_records_json_roundtrip() {
        let recs = vec![
            TxtRecord { name: "_acme-challenge.example.com".into(), value: "abc".into() },
            TxtRecord { name: "_acme-challenge.example.com".into(), value: "def".into() },
        ];
        let json = serde_json::to_string(&recs).unwrap();
        let back: Vec<TxtRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[1].value, "def");
    }
}
