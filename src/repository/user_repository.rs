use crate::error::AppError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub struct StoredCreateUser {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub email_blind_index: String,
    pub srp_salt: String,
    pub srp_verifier: String,
    pub date_of_birth: String,
    pub locale: String,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub accent_color: Option<String>,
    pub bio: Option<String>,
    pub pronouns: Option<String>,
}

#[derive(sqlx::FromRow)]
pub struct StoredUserRow {
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
    pub date_of_birth: String,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub accent_color: Option<String>,
    pub bio: Option<String>,
    pub pronouns: Option<String>,
    pub locale: String,
}

#[derive(sqlx::FromRow)]
pub struct DeletedUserCleanupRow {
    pub id: i64,
}

pub async fn create_user(
    pool: &PgPool,
    payload: StoredCreateUser,
) -> Result<StoredUserRow, AppError> {
    let user = sqlx::query_as::<_, StoredUserRow>(
        r#"
        INSERT INTO users (
            id, username, display_name, email, email_blind_index, srp_salt, srp_verifier,
            date_of_birth, locale, avatar_url, banner_url, accent_color, bio, pronouns
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13, $14
        )
        RETURNING
            id, username, display_name, email, email_verified,
            token_version, account_status, flags, last_login_at,
            created_at, updated_at, date_of_birth, avatar_url,
            banner_url, accent_color, bio, pronouns, locale
        "#,
    )
    .bind(payload.id)
    .bind(payload.username)
    .bind(payload.display_name)
    .bind(payload.email)
    .bind(payload.email_blind_index)
    .bind(payload.srp_salt)
    .bind(payload.srp_verifier)
    .bind(payload.date_of_birth)
    .bind(payload.locale)
    .bind(payload.avatar_url)
    .bind(payload.banner_url)
    .bind(payload.accent_color)
    .bind(payload.bio)
    .bind(payload.pronouns)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn get_user(pool: &PgPool, id: i64) -> Result<Option<StoredUserRow>, AppError> {
    let user = sqlx::query_as::<_, StoredUserRow>(
        r#"
        SELECT
            id, username, display_name, email, email_verified,
            token_version, account_status, flags, last_login_at,
            created_at, updated_at, date_of_birth, avatar_url,
            banner_url, accent_color, bio, pronouns, locale
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn update_avatar_url(
    pool: &PgPool,
    user_id: i64,
    avatar_url: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET avatar_url = $1 WHERE id = $2")
        .bind(avatar_url)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn list_deleted_users_pending_cleanup(
    pool: &PgPool,
    older_than: DateTime<Utc>,
) -> Result<Vec<DeletedUserCleanupRow>, AppError> {
    let rows = sqlx::query_as::<_, DeletedUserCleanupRow>(
        r#"
        SELECT id
        FROM users
        WHERE account_status = 'deleted'
          AND updated_at < $1
        "#,
    )
    .bind(older_than)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn anonymize_deleted_user(
    pool: &PgPool,
    user_id: i64,
    username: &str,
    display_name: &str,
    encrypted_email: &str,
    email_blind_index: &str,
    encrypted_date_of_birth: &str,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE users
        SET username = $2,
            display_name = $3,
            email = $4,
            email_blind_index = $5,
            email_verified = FALSE,
            srp_salt = NULL,
            srp_verifier = NULL,
            token_version = token_version + 1,
            totp_secret = NULL,
            totp_backup_codes = NULL,
            date_of_birth = $6,
            avatar_url = NULL,
            banner_url = NULL,
            accent_color = NULL,
            bio = NULL,
            pronouns = NULL,
            locale = 'und'
        WHERE id = $1
          AND account_status = 'deleted'
        "#,
    )
    .bind(user_id)
    .bind(username)
    .bind(display_name)
    .bind(encrypted_email)
    .bind(email_blind_index)
    .bind(encrypted_date_of_birth)
    .execute(pool)
    .await?;

    sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}
