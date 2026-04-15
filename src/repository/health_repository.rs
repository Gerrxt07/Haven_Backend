use crate::error::AppError;
use redis::Cmd;

pub async fn check_postgres(pool: &sqlx::PgPool) -> Result<(), AppError> {
    let _: i32 = sqlx::query_scalar("SELECT 1").fetch_one(pool).await?;
    Ok(())
}

pub async fn check_redis(pool: &deadpool_redis::Pool) -> Result<(), AppError> {
    let mut redis_conn = pool.get().await?;
    let _: String = Cmd::new().arg("PING").query_async(&mut redis_conn).await?;
    Ok(())
}
