use crate::error::AppError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub struct StoredCreateUser {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub email_blind_index: String,
    pub password_hash: String,
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

pub async fn create_user(
    pool: &PgPool,
    payload: StoredCreateUser,
) -> Result<StoredUserRow, AppError> {
    let user = sqlx::query_as::<_, StoredUserRow>(
        r#"
        INSERT INTO users (
            id, username, display_name, email, email_blind_index, password_hash,
            date_of_birth, locale, avatar_url, banner_url,
            accent_color, bio, pronouns
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10,
            $11, $12, $13
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
    .bind(payload.password_hash)
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
