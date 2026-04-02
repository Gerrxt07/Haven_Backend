use crate::{
    domain::auth::{LoginRequest, RefreshRequest, RegisterRequest},
    error::AppError,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};

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
) -> Result<Json<crate::domain::auth::AuthUserResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let user = service.register(payload).await?;
    Ok(Json(user))
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<crate::auth::AuthTokens>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let tokens = service.login(payload).await?;
    Ok(Json(tokens))
}

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<crate::auth::AuthTokens>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let tokens = service.refresh(payload).await?;
    Ok(Json(tokens))
}

async fn me(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<crate::domain::auth::AuthUserResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let current = service.me(&headers).await?;
    Ok(Json(current))
}
