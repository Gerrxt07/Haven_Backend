use crate::{
    domain::auth::{SessionRow, UserAuthRow},
    error::AppError,
};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};

pub struct NewRegistrationUser {
    pub user_id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub email_blind_index: String,
    pub srp_salt: String,
    pub srp_verifier: String,
    pub password_hash: Option<String>,
    pub date_of_birth: String,
    pub locale: String,
}

#[derive(sqlx::FromRow)]
pub struct StoredAuthUserResponseRow {
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

pub async fn insert_user_for_registration(
    pool: &PgPool,
    new_user: NewRegistrationUser,
) -> Result<StoredAuthUserResponseRow, AppError> {
    let result = sqlx::query_as::<_, StoredAuthUserResponseRow>(
        r#"
        INSERT INTO users (
            id, username, display_name, email, email_blind_index, srp_salt, srp_verifier, password_hash, date_of_birth, locale
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id,
            username,
            display_name,
            email,
            avatar_url,
            email_verified,
            (totp_secret IS NOT NULL) AS two_factor_enabled,
            account_status,
            token_version,
            created_at
        "#,
    )
    .bind(new_user.user_id)
    .bind(new_user.username)
    .bind(new_user.display_name)
    .bind(new_user.email)
    .bind(new_user.email_blind_index)
    .bind(new_user.srp_salt)
    .bind(new_user.srp_verifier)
    .bind(new_user.password_hash)
    .bind(new_user.date_of_birth)
    .bind(new_user.locale)
    .fetch_one(pool)
    .await;

    match result {
        Ok(user) => Ok(user),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => Err(
            AppError::Conflict("username or email already exists".to_string()),
        ),
        Err(err) => Err(AppError::Database(err)),
    }
}

pub async fn find_user_auth_by_email_blind_index(
    pool: &PgPool,
    email_blind_index: &str,
) -> Result<Option<UserAuthRow>, AppError> {
    let user = sqlx::query_as::<_, UserAuthRow>(
        r#"
        SELECT id, srp_salt, srp_verifier, password_hash, account_status, token_version, totp_secret, totp_backup_codes
        FROM users
        WHERE email_blind_index = $1
        "#,
    )
    .bind(email_blind_index)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn find_user_auth_by_id(pool: &PgPool, id: i64) -> Result<UserAuthRow, AppError> {
    let user = sqlx::query_as::<_, UserAuthRow>(
        r#"
        SELECT id, srp_salt, srp_verifier, password_hash, account_status, token_version, totp_secret, totp_backup_codes
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

pub async fn find_session(
    pool: &PgPool,
    session_id: i64,
    user_id: i64,
) -> Result<Option<SessionRow>, AppError> {
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

pub async fn find_current_user(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<StoredAuthUserResponseRow>, AppError> {
    let user = sqlx::query_as::<_, StoredAuthUserResponseRow>(
        r#"
        SELECT id,
            username,
            display_name,
            email,
            avatar_url,
            email_verified,
            (totp_secret IS NOT NULL) AS two_factor_enabled,
            account_status,
            token_version,
            created_at
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

#[derive(sqlx::FromRow)]
pub struct UserEmailStatusRow {
    pub id: i64,
    pub email_verified: bool,
}

pub async fn find_user_email_status_by_blind_index(
    pool: &PgPool,
    email_blind_index: &str,
) -> Result<Option<UserEmailStatusRow>, AppError> {
    let row = sqlx::query_as::<_, UserEmailStatusRow>(
        r#"
        SELECT id, email_verified
        FROM users
        WHERE email_blind_index = $1
        "#,
    )
    .bind(email_blind_index)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

pub async fn set_email_verified(pool: &PgPool, user_id: i64) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct EmailVerificationRow {
    pub id: i64,
    pub code_hash: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub async fn delete_email_verification_codes(pool: &PgPool, user_id: i64) -> Result<(), AppError> {
    sqlx::query("DELETE FROM email_verification_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_email_verification_code(
    pool: &PgPool,
    id: i64,
    user_id: i64,
    code_hash: String,
    expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO email_verification_codes (id, user_id, code_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(code_hash)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn find_latest_email_verification_code(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<EmailVerificationRow>, AppError> {
    let row = sqlx::query_as::<_, EmailVerificationRow>(
        r#"
        SELECT id, code_hash, expires_at, consumed_at, created_at
        FROM email_verification_codes
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn mark_email_verification_code_consumed(
    pool: &PgPool,
    code_id: i64,
) -> Result<(), AppError> {
    sqlx::query("UPDATE email_verification_codes SET consumed_at = NOW() WHERE id = $1")
        .bind(code_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct TotpSetupRow {
    pub secret: String,
    pub backup_codes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

pub async fn upsert_totp_setup(
    pool: &PgPool,
    user_id: i64,
    secret: String,
    backup_codes: Vec<String>,
    expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO totp_setups (user_id, secret, backup_codes, expires_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id) DO UPDATE
        SET secret = EXCLUDED.secret,
            backup_codes = EXCLUDED.backup_codes,
            expires_at = EXCLUDED.expires_at,
            created_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(secret)
    .bind(backup_codes)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn find_totp_setup(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<TotpSetupRow>, AppError> {
    let row = sqlx::query_as::<_, TotpSetupRow>(
        r#"
        SELECT secret, backup_codes, expires_at
        FROM totp_setups
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn delete_totp_setup(pool: &PgPool, user_id: i64) -> Result<(), AppError> {
    sqlx::query("DELETE FROM totp_setups WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_user_totp(
    pool: &PgPool,
    user_id: i64,
    secret: String,
    backup_codes: Vec<String>,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE users
        SET totp_secret = $2,
            totp_backup_codes = $3
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(secret)
    .bind(backup_codes)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn clear_user_totp(pool: &PgPool, user_id: i64) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE users
        SET totp_secret = NULL,
            totp_backup_codes = NULL
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_backup_codes(
    pool: &PgPool,
    user_id: i64,
    backup_codes: Vec<String>,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET totp_backup_codes = $2 WHERE id = $1")
        .bind(user_id)
        .bind(backup_codes)
        .execute(pool)
        .await?;
    Ok(())
}
