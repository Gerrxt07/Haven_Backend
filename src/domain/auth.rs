use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 32))]
    pub username: String,
    #[validate(length(min = 1, max = 64))]
    pub display_name: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 10, max = 128))]
    pub password: String,
    pub date_of_birth: NaiveDate,
    #[validate(length(min = 2, max = 10))]
    pub locale: String,
}

#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1, max = 128))]
    pub password: String,
    pub totp_code: Option<String>,
    pub backup_code: Option<String>,
}

#[derive(Deserialize, Validate)]
pub struct RefreshRequest {
    #[validate(length(min = 20))]
    pub refresh_token: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AuthUserResponse {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub avatar_url: Option<String>,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub account_status: String,
    pub token_version: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
pub struct UserAuthRow {
    pub id: i64,
    pub password_hash: String,
    pub account_status: String,
    pub token_version: i32,
    pub email_verified: bool,
    pub totp_secret: Option<String>,
    pub totp_backup_codes: Option<Vec<String>>,
}

#[derive(sqlx::FromRow)]
pub struct SessionRow {
    pub id: i64,
    pub refresh_token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub token_version: i32,
}

#[derive(Clone)]
pub struct AuthUser {
    pub id: i64,
}

#[derive(Deserialize, Validate)]
pub struct EmailVerificationRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Deserialize, Validate)]
pub struct EmailVerificationConfirmRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 6, max = 6))]
    pub code: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct TwoFactorSetupResponse {
    pub secret: String,
    pub otpauth_url: String,
    pub backup_codes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize, Validate)]
pub struct TwoFactorConfirmRequest {
    #[validate(length(min = 6, max = 8))]
    pub code: String,
}

#[derive(Deserialize, Validate)]
pub struct TwoFactorDisableRequest {
    pub code: Option<String>,
    pub backup_code: Option<String>,
}
