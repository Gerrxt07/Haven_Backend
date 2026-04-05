use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

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
