use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub password_hash: String,
    pub date_of_birth: NaiveDate,
    pub locale: String,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub accent_color: Option<String>,
    pub bio: Option<String>,
    pub pronouns: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub email_verified: bool,
    pub token_version: i32,
    pub account_status: String,
    pub flags: i32,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub date_of_birth: NaiveDate,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub accent_color: Option<String>,
    pub bio: Option<String>,
    pub pronouns: Option<String>,
    pub locale: String,
}

#[derive(Serialize)]
pub struct AvatarUploadResponse {
    pub avatar_url: String,
    pub width: u32,
    pub height: u32,
    pub size_bytes: usize,
    pub format: &'static str,
}
