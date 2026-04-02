use crate::{error::AppError, state::AppState};
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
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

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", post(create_user))
        .route("/users/{id}", get(get_user))
}

async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<User>, AppError> {
    if payload.username.trim().is_empty() {
        return Err(AppError::BadRequest("username is required".to_string()));
    }
    if payload.display_name.trim().is_empty() {
        return Err(AppError::BadRequest("display_name is required".to_string()));
    }
    if payload.email.trim().is_empty() {
        return Err(AppError::BadRequest("email is required".to_string()));
    }

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
    .fetch_one(&state.pg_pool)
    .await?;

    Ok(Json(user))
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<User>, AppError> {
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
    .fetch_optional(&state.pg_pool)
    .await?;

    match user {
        Some(user) => Ok(Json(user)),
        None => Err(AppError::NotFound),
    }
}
