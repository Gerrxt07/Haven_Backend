use crate::{
    domain::auth::{AuthUserResponse, SessionRow, UserAuthRow},
    error::AppError,
};
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{PgPool, Postgres, Transaction};

pub struct NewRegistrationUser {
    pub user_id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub password_hash: String,
    pub date_of_birth: NaiveDate,
    pub locale: String,
}

pub async fn insert_user_for_registration(
    pool: &PgPool,
    new_user: NewRegistrationUser,
) -> Result<AuthUserResponse, AppError> {
    let result = sqlx::query_as::<_, AuthUserResponse>(
        r#"
        INSERT INTO users (
            id, username, display_name, email, password_hash, date_of_birth, locale
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, username, display_name, email, account_status, token_version, created_at
        "#,
    )
    .bind(new_user.user_id)
    .bind(new_user.username)
    .bind(new_user.display_name)
    .bind(new_user.email)
    .bind(new_user.password_hash)
    .bind(new_user.date_of_birth)
    .bind(new_user.locale)
    .fetch_one(pool)
    .await;

    match result {
        Ok(user) => Ok(user),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            Err(AppError::Conflict("username or email already exists".to_string()))
        }
        Err(err) => Err(AppError::Database(err)),
    }
}

pub async fn find_user_auth_by_email(pool: &PgPool, email: &str) -> Result<Option<UserAuthRow>, AppError> {
    let user = sqlx::query_as::<_, UserAuthRow>(
        r#"
        SELECT id, password_hash, account_status, token_version
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn find_user_auth_by_id(pool: &PgPool, id: i64) -> Result<UserAuthRow, AppError> {
    let user = sqlx::query_as::<_, UserAuthRow>(
        r#"
        SELECT id, password_hash, account_status, token_version
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn insert_auth_session(
    pool: &PgPool,
    session_id: i64,
    user_id: i64,
    refresh_token_hash: String,
    expires_at: DateTime<Utc>,
    token_version: i32,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO auth_sessions (id, user_id, refresh_token_hash, expires_at, token_version)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(refresh_token_hash)
    .bind(expires_at)
    .bind(token_version)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn update_last_login(pool: &PgPool, user_id: i64) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn find_session(pool: &PgPool, session_id: i64, user_id: i64) -> Result<Option<SessionRow>, AppError> {
    let session = sqlx::query_as::<_, SessionRow>(
        r#"
        SELECT id, refresh_token_hash, expires_at, revoked_at, token_version
        FROM auth_sessions
        WHERE id = $1 AND user_id = $2
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(session)
}

pub async fn begin_tx(pool: &PgPool) -> Result<Transaction<'_, Postgres>, AppError> {
    Ok(pool.begin().await?)
}

pub async fn revoke_session(
    tx: &mut Transaction<'_, Postgres>,
    session_id: i64,
) -> Result<(), AppError> {
    sqlx::query("UPDATE auth_sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

pub async fn insert_auth_session_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: i64,
    user_id: i64,
    refresh_token_hash: String,
    expires_at: DateTime<Utc>,
    token_version: i32,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO auth_sessions (id, user_id, refresh_token_hash, expires_at, token_version)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind(refresh_token_hash)
    .bind(expires_at)
    .bind(token_version)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

pub async fn commit_tx(tx: Transaction<'_, Postgres>) -> Result<(), AppError> {
    tx.commit().await?;
    Ok(())
}

pub async fn find_current_user(pool: &PgPool, user_id: i64) -> Result<Option<AuthUserResponse>, AppError> {
    let user = sqlx::query_as::<_, AuthUserResponse>(
        r#"
        SELECT id, username, display_name, email, account_status, token_version, created_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn find_status_and_token_version(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<(String, i32)>, AppError> {
    let row = sqlx::query_as::<_, (String, i32)>(
        "SELECT account_status, token_version FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}
