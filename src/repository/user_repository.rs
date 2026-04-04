use crate::{
    domain::user::{CreateUserRequest, User},
    error::AppError,
};
use sqlx::PgPool;

pub async fn create_user(pool: &PgPool, payload: CreateUserRequest) -> Result<User, AppError> {
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (
            id, username, display_name, email, password_hash,
            date_of_birth, locale, avatar_url, banner_url,
            accent_color, bio, pronouns
        )
        VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9,
            $10, $11, $12
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

pub async fn get_user(pool: &PgPool, id: i64) -> Result<Option<User>, AppError> {
    let user = sqlx::query_as::<_, User>(
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
