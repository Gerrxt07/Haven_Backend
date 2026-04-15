use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct SendFriendRequest {
    #[validate(length(min = 3, max = 32))]
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct FriendRequest {
    pub id: i64,
    pub from_user_id: i64,
    pub from_username: String,
    pub from_display_name: String,
    pub from_avatar_url: Option<String>,
    pub to_user_id: i64,
    pub to_username: String,
    pub to_display_name: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Friend {
    pub id: i64,
    pub user_id: i64,
    pub friend_user_id: i64,
    pub friend_username: String,
    pub friend_display_name: String,
    pub friend_avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
}
