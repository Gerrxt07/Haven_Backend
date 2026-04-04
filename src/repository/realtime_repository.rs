use crate::{domain::realtime::RealtimeEvent, error::AppError};
use futures_util::StreamExt;
use redis::AsyncCommands;

const PRESENCE_TTL_SECONDS: u64 = 90;
const SESSION_TTL_SECONDS: u64 = 86_400;
const FANOUT_CHANNEL: &str = "haven:events";

pub async fn cache_presence(
    pool: &deadpool_redis::Pool,
    user_id: i64,
    status: &str,
) -> Result<(), AppError> {
    let mut conn = pool.get().await?;
    let key = format!("presence:user:{user_id}");
    let _: () = conn.set_ex(key, status, PRESENCE_TTL_SECONDS).await?;
    Ok(())
}

pub async fn cache_session(
    pool: &deadpool_redis::Pool,
    session_id: &str,
    encrypted_payload: &str,
) -> Result<(), AppError> {
    let mut conn = pool.get().await?;
    let key = format!("session:ws:{session_id}");
    let _: () = conn
        .set_ex(key, encrypted_payload, SESSION_TTL_SECONDS)
        .await?;
    Ok(())
}

pub async fn remove_session(pool: &deadpool_redis::Pool, session_id: &str) -> Result<(), AppError> {
    let mut conn = pool.get().await?;
    let key = format!("session:ws:{session_id}");
    let _: i32 = conn.del(key).await?;
    Ok(())
}

pub async fn publish_event(
    pool: &deadpool_redis::Pool,
    event: &RealtimeEvent,
) -> Result<(), AppError> {
    let mut conn = pool.get().await?;
    let payload = serde_json::to_string(event)
        .map_err(|_| AppError::BadRequest("failed to serialize realtime event".to_string()))?;
    let _: i32 = redis::cmd("PUBLISH")
        .arg(FANOUT_CHANNEL)
        .arg(payload)
        .query_async(&mut *conn)
        .await?;
    Ok(())
}

pub async fn subscribe_events(
    dragonfly_url: &str,
    tx: tokio::sync::broadcast::Sender<RealtimeEvent>,
) -> Result<(), AppError> {
    let client = redis::Client::open(dragonfly_url)
        .map_err(|_| AppError::BadRequest("invalid dragonfly url".to_string()))?;

    let mut pubsub = client.get_async_pubsub().await.map_err(AppError::Cache)?;

    pubsub
        .subscribe(FANOUT_CHANNEL)
        .await
        .map_err(AppError::Cache)?;

    let mut stream = pubsub.on_message();

    while let Some(msg) = stream.next().await {
        let payload: String = match msg.get_payload() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let event: RealtimeEvent = match serde_json::from_str(&payload) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let _ = tx.send(event);
    }

    Ok(())
}
