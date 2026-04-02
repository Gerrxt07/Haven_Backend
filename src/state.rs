use crate::{auth::TokenManager, security::SimpleRateLimiter};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pg_pool: sqlx::PgPool,
    pub redis_pool: deadpool_redis::Pool,
    pub token_manager: Arc<TokenManager>,
    pub rate_limiter: Arc<SimpleRateLimiter>,
}
