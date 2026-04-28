use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::domain::e2ee::RecipientKeyBoxInput;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateServerRequest {
    #[validate(length(min = 2, max = 100))]
    pub name: String,
    #[validate(length(min = 2, max = 120))]
    pub slug: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub is_public: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Server {
    pub id: i64,
    pub owner_user_id: i64,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateChannelRequest {
    #[validate(length(min = 1, max = 80))]
    pub name: String,
    pub topic: Option<String>,
    #[validate(length(min = 4, max = 16))]
    pub channel_type: Option<String>,
    pub position: Option<i32>,
    pub is_private: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateChannelDirectRequest {
    pub server_id: i64,
    #[validate(length(min = 1, max = 80))]
    pub name: String,
    pub topic: Option<String>,
    #[validate(length(min = 4, max = 16))]
    pub channel_type: Option<String>,
    pub position: Option<i32>,
    pub is_private: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Channel {
    pub id: i64,
    pub server_id: i64,
    pub name: String,
    pub topic: Option<String>,
    pub channel_type: String,
    pub position: i32,
    pub is_private: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateMessageRequest {
    pub content: Option<String>,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub aad: Option<String>,
    pub algorithm: Option<String>,
    pub recipient_key_boxes: Option<Vec<RecipientKeyBoxInput>>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateMessageDirectRequest {
    pub channel_id: i64,
    pub content: Option<String>,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub aad: Option<String>,
    pub algorithm: Option<String>,
    pub recipient_key_boxes: Option<Vec<RecipientKeyBoxInput>>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Message {
    pub id: i64,
    pub channel_id: i64,
    pub author_user_id: i64,
    pub author_avatar_url: Option<String>,
    pub content: String,
    pub is_encrypted: bool,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub aad: Option<String>,
    pub algorithm: Option<String>,
    pub edited_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub before: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateDmThreadRequest {
    pub peer_user_id: i64,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct DmThread {
    pub id: i64,
    pub user_a_id: i64,
    pub user_b_id: i64,
    pub created_by_user_id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct DmThreadSummary {
    pub id: i64,
    pub peer_user_id: i64,
    pub peer_username: String,
    pub peer_display_name: String,
    pub peer_avatar_url: Option<String>,
    pub last_message_preview: Option<String>,
    pub last_message_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateDmMessageRequest {
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub aad: Option<String>,
    pub algorithm: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct DmMessage {
    pub id: i64,
    pub thread_id: i64,
    pub author_user_id: i64,
    pub author_avatar_url: Option<String>,
    pub content: String,
    pub is_encrypted: bool,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub aad: Option<String>,
    pub algorithm: Option<String>,
    pub edited_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
