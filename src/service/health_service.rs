use crate::{repository::health_repository, state::AppState};
use axum::http::StatusCode;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub postgres: &'static str,
    pub dragonfly: &'static str,
}

#[derive(Clone)]
pub struct HealthService {
    state: AppState,
}

impl HealthService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn health(&self) -> (StatusCode, HealthResponse) {
        let postgres_ok = health_repository::check_postgres(&self.state.pg_pool)
            .await
            .is_ok();
        let dragonfly_ok = health_repository::check_redis(&self.state.redis_pool)
            .await
            .is_ok();

        let all_ok = postgres_ok && dragonfly_ok;
        let status_code = if all_ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };

        let response = HealthResponse {
            status: if all_ok { "ok" } else { "degraded" },
            postgres: if postgres_ok { "ok" } else { "down" },
            dragonfly: if dragonfly_ok { "ok" } else { "down" },
        };

        (status_code, response)
    }
}
