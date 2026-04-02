use crate::{error::AppError, repository::health_repository, state::AppState};
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

    pub async fn health(&self) -> Result<HealthResponse, AppError> {
        health_repository::check_postgres(&self.state.pg_pool).await?;
        health_repository::check_redis(&self.state.redis_pool).await?;

        Ok(HealthResponse {
            status: "ok",
            postgres: "ok",
            dragonfly: "ok",
        })
    }
}
