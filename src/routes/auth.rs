use crate::{
    auth::{generate_id, hash_password, sha256_hex, verify_password, AuthTokens},
    error::AppError,
    state::AppState,
};
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
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
    pub account_status: String,
    pub token_version: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct UserAuthRow {
    id: i64,
    password_hash: String,
    account_status: String,
    token_version: i32,
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: i64,
    refresh_token_hash: String,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    token_version: i32,
}

#[derive(Clone)]
pub struct AuthUser {
    pub id: i64,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/me", get(me))
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthUserResponse>, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let password_hash = hash_password(&payload.password)?;
    let user_id = generate_id();

    let result = sqlx::query_as::<_, AuthUserResponse>(
        r#"
        INSERT INTO users (
            id, username, display_name, email, password_hash, date_of_birth, locale
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, username, display_name, email, account_status, token_version, created_at
        "#,
    )
    .bind(user_id)
    .bind(payload.username.trim().to_lowercase())
    .bind(payload.display_name.trim())
    .bind(payload.email.trim().to_lowercase())
    .bind(password_hash)
    .bind(payload.date_of_birth)
    .bind(payload.locale.trim().to_lowercase())
    .fetch_one(&state.pg_pool)
    .await;

    match result {
        Ok(user) => {
            tracing::info!(event = "auth.register", user_id = user.id, email = user.email, "user registered");
            Ok(Json(user))
        }
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            Err(AppError::Conflict("username or email already exists".to_string()))
        }
        Err(err) => Err(AppError::Database(err)),
    }
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthTokens>, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let user = sqlx::query_as::<_, UserAuthRow>(
        r#"
        SELECT id, password_hash, account_status, token_version
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(payload.email.trim().to_lowercase())
    .fetch_optional(&state.pg_pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if user.account_status != "active" {
        tracing::warn!(event = "auth.login.blocked", user_id = user.id, status = user.account_status, "blocked login due to account status");
        return Err(AppError::Forbidden);
    }

    if !verify_password(&user.password_hash, &payload.password) {
        tracing::warn!(event = "auth.login.failed", email = payload.email, "invalid password");
        return Err(AppError::Unauthorized);
    }

    let session_id = generate_id();
    let tokens = state
        .token_manager
        .issue_tokens(user.id, session_id, user.token_version)?;

    let refresh_hash = sha256_hex(&tokens.refresh_token);
    let refresh_expires = Utc::now() + chrono::Duration::days(state.token_manager.refresh_ttl_days());

    sqlx::query(
        r#"
        INSERT INTO auth_sessions (id, user_id, refresh_token_hash, expires_at, token_version)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(session_id)
    .bind(user.id)
    .bind(refresh_hash)
    .bind(refresh_expires)
    .bind(user.token_version)
    .execute(&state.pg_pool)
    .await?;

    sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(user.id)
        .execute(&state.pg_pool)
        .await?;

    tracing::info!(event = "auth.login", user_id = user.id, session_id, "login successful");
    Ok(Json(tokens))
}

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<AuthTokens>, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let claims = state
        .token_manager
        .parse_and_validate(&payload.refresh_token, "refresh")?;

    let session = sqlx::query_as::<_, SessionRow>(
        r#"
        SELECT id, refresh_token_hash, expires_at, revoked_at, token_version
        FROM auth_sessions
        WHERE id = $1 AND user_id = $2
        "#,
    )
    .bind(claims.session_id)
    .bind(claims.user_id)
    .fetch_optional(&state.pg_pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if session.revoked_at.is_some() || session.expires_at < Utc::now() {
        return Err(AppError::Unauthorized);
    }

    if session.token_version != claims.token_version {
        return Err(AppError::Unauthorized);
    }

    let incoming_hash = sha256_hex(&payload.refresh_token);
    if session.refresh_token_hash != incoming_hash {
        return Err(AppError::Unauthorized);
    }

    let user = sqlx::query_as::<_, UserAuthRow>(
        r#"
        SELECT id, password_hash, account_status, token_version
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(claims.user_id)
    .fetch_one(&state.pg_pool)
    .await?;

    if user.account_status != "active" {
        return Err(AppError::Forbidden);
    }

    let new_session_id = generate_id();
    let tokens = state
        .token_manager
        .issue_tokens(user.id, new_session_id, user.token_version)?;

    let new_refresh_hash = sha256_hex(&tokens.refresh_token);
    let new_refresh_expires = Utc::now() + chrono::Duration::days(state.token_manager.refresh_ttl_days());

    let mut tx = state.pg_pool.begin().await?;

    sqlx::query("UPDATE auth_sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session.id)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        r#"
        INSERT INTO auth_sessions (id, user_id, refresh_token_hash, expires_at, token_version)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(new_session_id)
    .bind(user.id)
    .bind(new_refresh_hash)
    .bind(new_refresh_expires)
    .bind(user.token_version)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(event = "auth.refresh", user_id = user.id, old_session = session.id, new_session = new_session_id, "token refresh successful");
    Ok(Json(tokens))
}

async fn me(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<AuthUserResponse>, AppError> {
    let user = authenticate_from_headers(&headers, &state).await?;

    let current = sqlx::query_as::<_, AuthUserResponse>(
        r#"
        SELECT id, username, display_name, email, account_status, token_version, created_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user.id)
    .fetch_optional(&state.pg_pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    Ok(Json(current))
}

async fn authenticate_from_headers(headers: &HeaderMap, state: &AppState) -> Result<AuthUser, AppError> {
    let bearer = extract_bearer(headers)?;
    let claims = state.token_manager.parse_and_validate(&bearer, "access")?;

    let status_row = sqlx::query_as::<_, (String, i32)>(
        "SELECT account_status, token_version FROM users WHERE id = $1",
    )
    .bind(claims.user_id)
    .fetch_optional(&state.pg_pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if status_row.0 != "active" {
        return Err(AppError::Forbidden);
    }

    if status_row.1 != claims.token_version {
        return Err(AppError::Unauthorized);
    }

    Ok(AuthUser {
        id: claims.user_id,
    })
}

fn extract_bearer(headers: &HeaderMap) -> Result<String, AppError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized)?;

    Ok(token.to_string())
}
