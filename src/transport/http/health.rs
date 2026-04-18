use crate::{service::ServiceFactory, state::AppState};
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};

pub fn router() -> Router<AppState> {
    Router::new().route("/health", get(health))
}

async fn health(
    State(state): State<AppState>,
) -> (
    StatusCode,
    Json<crate::service::health_service::HealthResponse>,
) {
    let service = ServiceFactory::new(state).health();
    let (status, response) = service.health().await;
    (status, Json(response))
}
