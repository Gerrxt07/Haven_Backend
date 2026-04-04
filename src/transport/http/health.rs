use crate::{error::AppError, service::ServiceFactory, state::AppState};
use axum::{extract::State, routing::get, Json, Router};

pub fn router() -> Router<AppState> {
    Router::new().route("/health", get(health))
}

async fn health(
    State(state): State<AppState>,
) -> Result<Json<crate::service::health_service::HealthResponse>, AppError> {
    let service = ServiceFactory::new(state).health();
    let response = service.health().await?;
    Ok(Json(response))
}
