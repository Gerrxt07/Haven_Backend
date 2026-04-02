mod auth;
mod config;
mod error;
mod routes;
mod security;
mod state;

use auth::TokenManager;
use axum::{middleware::from_fn_with_state, routing::get, Router};
use config::Config;
use deadpool_redis::Runtime;
use security::{rate_limit_middleware, SimpleRateLimiter};
use sqlx::{postgres::PgPoolOptions, Connection};
use state::AppState;
use std::{sync::Arc, time::Duration};
use std::net::SocketAddr;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

fn is_valid_db_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

async fn ensure_database_exists(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if !is_valid_db_name(&config.postgres_db) {
        return Err(format!(
            "invalid POSTGRES_DB '{}': only [a-zA-Z0-9_] allowed",
            config.postgres_db
        )
        .into());
    }

    let mut conn = sqlx::PgConnection::connect(&config.postgres_admin_url).await?;
    let create_db_sql = format!("CREATE DATABASE \"{}\"", config.postgres_db);

    match sqlx::query(&create_db_sql).execute(&mut conn).await {
        Ok(_) => info!("created postgres database '{}'", config.postgres_db),
        Err(err) => {
            if let sqlx::Error::Database(db_err) = &err {
                if db_err.code().as_deref() == Some("42P04") {
                    info!("postgres database '{}' already exists", config.postgres_db);
                    return Ok(());
                }
            }
            return Err(err.into());
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;

    ensure_database_exists(&config).await?;

    let pg_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.postgres_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pg_pool).await?;

    let redis_cfg = deadpool_redis::Config::from_url(config.dragonfly_url.clone());
    let redis_pool = redis_cfg.create_pool(Some(Runtime::Tokio1))?;
    let token_manager = Arc::new(TokenManager::new(
        &config.paseto_local_key,
        config.access_token_ttl_minutes,
        config.refresh_token_ttl_days,
    ));
    let rate_limiter = Arc::new(SimpleRateLimiter::new(
        config.rate_limit_requests_per_minute,
        Duration::from_secs(60),
    ));

    let state = AppState {
        pg_pool,
        redis_pool,
        token_manager,
        rate_limiter,
    };

    let cors_layer = if config.cors_allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
            .allow_origin(Any)
    } else {
        let origins = config
            .cors_allowed_origins
            .iter()
            .filter_map(|origin| origin.parse::<axum::http::HeaderValue>().ok())
            .collect::<Vec<_>>();

        CorsLayer::new()
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
            .allow_origin(origins)
    };

    let api_router = routes::router().route_layer(from_fn_with_state(state.clone(), rate_limit_middleware));

    let app = Router::new()
        .route("/", get(|| async { "haven-backend" }))
        .nest("/api/v1", api_router)
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(config.request_body_limit_bytes))
        .layer(cors_layer)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("haven-backend listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
