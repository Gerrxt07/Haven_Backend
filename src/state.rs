use crate::{auth::TokenManager, crypto::CryptoManager, security::SimpleRateLimiter};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::domain::realtime::RealtimeEvent;

#[derive(Clone)]
pub struct AppState {
    pub pg_pool: sqlx::PgPool,
    pub redis_pool: deadpool_redis::Pool,
    pub dragonfly_url: String,
    pub token_manager: Arc<TokenManager>,
    pub crypto_manager: Arc<CryptoManager>,
    pub rate_limiter: Arc<SimpleRateLimiter>,
    pub realtime_tx: broadcast::Sender<RealtimeEvent>,
}
