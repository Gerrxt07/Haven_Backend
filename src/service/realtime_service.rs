use crate::{
    domain::realtime::RealtimeEvent, error::AppError, repository::realtime_repository,
    state::AppState,
};

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

    pub fn publish(&self, event: RealtimeEvent) -> Result<(), AppError> {
        self.state
            .realtime_tx
            .send(event)
            .map(|_| ())
            .map_err(|_| AppError::BadRequest("failed to publish realtime event".to_string()))
    }

    pub async fn publish_with_fanout(&self, event: RealtimeEvent) -> Result<(), AppError> {
        self.publish(event.clone())?;
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
            if let Err(err) = realtime_repository::subscribe_events(&dragonfly_url, tx).await {
                tracing::error!(event = "realtime.fanout.bridge.failed", error = %err);
            }
        });
    }
}
