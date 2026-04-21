use crate::error::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

pub const MAX_E2EE_PAYLOAD_BYTES: usize = 65_536;

#[derive(Debug, Deserialize, Validate)]
pub struct OneTimePrekeyInput {
    pub id: i64,
    #[validate(length(min = 20, max = 8192))]
    pub prekey: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UploadKeyBundleRequest {
    #[validate(length(min = 20, max = 8192))]
    pub identity_key: String,
    pub signed_prekey_id: i64,
    #[validate(length(min = 20, max = 8192))]
    pub signed_prekey: String,
    #[validate(length(min = 20, max = 8192))]
    pub signed_prekey_signature: String,
    pub one_time_prekeys: Vec<OneTimePrekeyInput>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PublicKeyBundle {
    pub user_id: i64,
    pub identity_key: String,
    pub signed_prekey_id: i64,
    pub signed_prekey: String,
    pub signed_prekey_signature: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct KeyBundleWithPrekey {
    pub user_id: i64,
    pub identity_key: String,
    pub signed_prekey_id: i64,
    pub signed_prekey: String,
    pub signed_prekey_signature: String,
    pub one_time_prekey_id: i64,
    pub one_time_prekey: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ClaimPrekeyRequest {
    pub target_user_id: i64,
}

#[derive(Debug, Deserialize, Validate, Clone)]
pub struct RecipientKeyBoxInput {
    pub recipient_user_id: i64,
    #[validate(length(min = 20, max = 16384))]
    pub encrypted_message_key: String,
    pub one_time_prekey_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewMessageRecipientKey {
    pub message_id: i64,
    pub recipient_user_id: i64,
    pub encrypted_message_key: String,
    pub one_time_prekey_id: Option<i64>,
}

pub fn validate_e2ee_payload_size(
    ciphertext: Option<&str>,
    nonce: Option<&str>,
    aad: Option<&str>,
) -> Result<(), AppError> {
    let total_len =
        ciphertext.map_or(0, str::len) + nonce.map_or(0, str::len) + aad.map_or(0, str::len);

    if total_len > MAX_E2EE_PAYLOAD_BYTES {
        return Err(AppError::PayloadTooLarge(format!(
            "combined ciphertext, nonce, and aad exceed {MAX_E2EE_PAYLOAD_BYTES} bytes"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_e2ee_payload_size, MAX_E2EE_PAYLOAD_BYTES};

    #[test]
    fn accepts_payload_at_limit() {
        let ciphertext = "a".repeat(MAX_E2EE_PAYLOAD_BYTES - 6);
        validate_e2ee_payload_size(Some(&ciphertext), Some("123"), Some("456"))
            .expect("payload at limit should pass");
    }

    #[test]
    fn rejects_payload_above_limit() {
        let ciphertext = "a".repeat(MAX_E2EE_PAYLOAD_BYTES);
        let err = validate_e2ee_payload_size(Some(&ciphertext), Some("123"), Some("456"))
            .expect_err("payload above limit must fail");

        assert!(err.to_string().contains("payload too large"));
    }
}
