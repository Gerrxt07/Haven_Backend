use crate::{
    domain::realtime::RealtimeEvent, error::AppError, repository::realtime_repository,
    state::AppState,
};
use std::time::Duration;

#[derive(Clone)]
pub struct RealtimeService {
    state: AppState,
}

impl RealtimeService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<RealtimeEvent> {
        self.state.realtime_tx.subscribe()
    }

    pub async fn publish_with_fanout(&self, event: RealtimeEvent) -> Result<(), AppError> {
        realtime_repository::publish_event(&self.state.redis_pool, &event).await
    }

    pub async fn set_presence(&self, user_id: i64, status: &str) -> Result<(), AppError> {
        realtime_repository::cache_presence(&self.state.redis_pool, user_id, status).await
    }

    pub async fn cache_ws_session(&self, session_id: &str, user_id: i64) -> Result<(), AppError> {
        let encrypted = self
            .state
            .crypto_manager
            .encrypt_string(&user_id.to_string(), Some(session_id.as_bytes()))?;

        realtime_repository::cache_session(&self.state.redis_pool, session_id, &encrypted).await
    }

    pub async fn remove_ws_session(&self, session_id: &str) -> Result<(), AppError> {
        realtime_repository::remove_session(&self.state.redis_pool, session_id).await
    }

    pub fn spawn_fanout_bridge(&self) {
        let dragonfly_url = self.state.dragonfly_url.clone();
        let tx = self.state.realtime_tx.clone();

        tokio::spawn(async move {
            let mut reconnect_attempt: u32 = 0;
            loop {
                match realtime_repository::subscribe_events(&dragonfly_url, tx.clone()).await {
                    Ok(()) => {
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        tracing::warn!(
                            event = "realtime.fanout.bridge.ended",
                            reconnect_attempt,
                            "realtime fanout bridge ended unexpectedly; reconnecting"
                        );
                    }
                    Err(err) => {
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        tracing::error!(
                            event = "realtime.fanout.bridge.failed",
                            reconnect_attempt,
                            error = %err
                        );
                    }
                }

                let base_delay_ms = 500_u64.saturating_mul(
                    2_u64.saturating_pow(reconnect_attempt.saturating_sub(1).min(6)),
                );
                let jitter_ms = (u64::from(rand::random::<u16>()) % 250).saturating_add(50);
                let delay =
                    Duration::from_millis(base_delay_ms.min(30_000).saturating_add(jitter_ms));
                tokio::time::sleep(delay).await;
            }
        });
    }
}
