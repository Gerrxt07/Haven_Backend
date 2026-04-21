use crate::error::AppError;
use redis::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};

pub async fn get_json<T: DeserializeOwned>(
    pool: &deadpool_redis::Pool,
    key: &str,
) -> Result<Option<T>, AppError> {
    let mut conn = pool.get().await?;
    let value: Option<String> = conn.get(key).await?;

    match value {
        Some(raw) => {
            let parsed = serde_json::from_str::<T>(&raw)
                .map_err(|e| AppError::Service(format!("failed to decode cache payload: {e}")))?;
            Ok(Some(parsed))
        }
        None => Ok(None),
    }
}

pub async fn set_json<T: Serialize>(
    pool: &deadpool_redis::Pool,
    key: &str,
    value: &T,
    ttl_seconds: u64,
) -> Result<(), AppError> {
    let mut conn = pool.get().await?;
    let payload = serde_json::to_string(value)
        .map_err(|e| AppError::Service(format!("failed to encode cache payload: {e}")))?;
    let _: () = conn.set_ex(key, payload, ttl_seconds).await?;
    Ok(())
}

pub async fn set_json_indexed<T: Serialize>(
    pool: &deadpool_redis::Pool,
    index_key: &str,
    key: &str,
    value: &T,
    ttl_seconds: u64,
) -> Result<(), AppError> {
    let mut conn = pool.get().await?;
    let payload = serde_json::to_string(value)
        .map_err(|e| AppError::Service(format!("failed to encode cache payload: {e}")))?;

    let _: () = redis::pipe()
        .atomic()
        .cmd("SETEX")
        .arg(key)
        .arg(ttl_seconds)
        .arg(payload)
        .ignore()
        .cmd("SADD")
        .arg(index_key)
        .arg(key)
        .ignore()
        .cmd("EXPIRE")
        .arg(index_key)
        .arg(ttl_seconds)
        .ignore()
        .query_async(&mut *conn)
        .await?;

    Ok(())
}

pub async fn del_key(pool: &deadpool_redis::Pool, key: &str) -> Result<(), AppError> {
    let mut conn = pool.get().await?;
    let _: i32 = conn.del(key).await?;
    Ok(())
}

pub fn auth_status_cache_key(user_id: i64) -> String {
    format!("cache:auth:status:{user_id}")
}

pub async fn invalidate_auth_status_cache(
    pool: &deadpool_redis::Pool,
    user_id: i64,
) -> Result<(), AppError> {
    del_key(pool, &auth_status_cache_key(user_id)).await
}

pub async fn invalidate_indexed_keys(
    pool: &deadpool_redis::Pool,
    index_key: &str,
) -> Result<(), AppError> {
    let mut conn = pool.get().await?;
    let keys: Vec<String> = conn.smembers(index_key).await?;

    if !keys.is_empty() {
        let _: () = redis::pipe()
            .atomic()
            .del(&keys)
            .ignore()
            .del(index_key)
            .ignore()
            .query_async(&mut *conn)
            .await?;
        return Ok(());
    }

    let _: i32 = conn.del(index_key).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::auth_status_cache_key;

    #[test]
    fn auth_status_cache_key_is_namespaced() {
        assert_eq!(auth_status_cache_key(42), "cache:auth:status:42");
    }
}
