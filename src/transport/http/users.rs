use crate::{
    domain::user::CreateUserRequest,
    error::AppError,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", post(create_user))
        .route("/users/{id}", get(get_user))
}

async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<crate::domain::user::User>, AppError> {
    let service = ServiceFactory::new(state).user();
    let user = service.create_user(payload).await?;
    Ok(Json(user))
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<crate::domain::user::User>, AppError> {
    let service = ServiceFactory::new(state).user();
    let user = service.get_user(id).await?;
    Ok(Json(user))
}
