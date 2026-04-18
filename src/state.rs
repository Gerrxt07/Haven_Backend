use crate::{auth::TokenManager, crypto::CryptoManager, email::EmailClient, security::SimpleRateLimiter, service::srp_service::SrpService};
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
    pub email_client: Arc<EmailClient>,
    pub rate_limiter: Arc<SimpleRateLimiter>,
    pub email_verify_ip_limiter: Arc<SimpleRateLimiter>,
    pub email_verify_email_limiter: Arc<SimpleRateLimiter>,
    pub realtime_tx: broadcast::Sender<RealtimeEvent>,
    pub avatar_storage_dir: String,
    pub srp_service: Arc<SrpService>,
}
