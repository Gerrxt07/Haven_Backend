use crate::{error::AppError, state::AppState};
use axum::{extract::State, routing::get, Json, Router};
use redis::Cmd;
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    postgres: &'static str,
    dragonfly: &'static str,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/health", get(health))
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, AppError> {
    let _: i64 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&state.pg_pool)
        .await?;

    let mut redis_conn = state.redis_pool.get().await?;
    let _: String = Cmd::new().arg("PING").query_async(&mut redis_conn).await?;

    Ok(Json(HealthResponse {
        status: "ok",
        postgres: "ok",
        dragonfly: "ok",
    }))
}
