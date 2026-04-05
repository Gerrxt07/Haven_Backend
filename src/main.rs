mod auth;
mod config;
mod crypto;
mod domain;
mod error;
mod repository;
mod routes;
mod security;
mod service;
mod state;
mod transport;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use auth::TokenManager;
use axum::{middleware::from_fn_with_state, routing::get, Router};
use config::Config;
use crypto::CryptoManager;
use deadpool_redis::Runtime;
use security::{rate_limit_middleware, SimpleRateLimiter};
use service::realtime_service::RealtimeService;
use sqlx::{postgres::PgPoolOptions, Connection};
use state::AppState;
use std::net::SocketAddr;
use std::path::Path;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
use std::{sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{info, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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
    let config = Config::from_env()?;
    config.validate_security()?;

    let log_file_path = Path::new(&config.backend_log_file);
    if let Some(parent_dir) = log_file_path.parent() {
        if !parent_dir.as_os_str().is_empty() {
            std::fs::create_dir_all(parent_dir)?;
        }
    }

    let log_dir = log_file_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let log_filename = log_file_path
        .file_name()
        .ok_or("BACKEND_LOG_FILE must include a filename")?
        .to_string_lossy()
        .to_string();

    let file_appender = tracing_appender::rolling::never(log_dir, log_filename);
    let (file_writer, _file_guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "haven_backend=trace,tower_http=info,axum=info,sqlx=warn,sqlx::query=warn,tokio_tungstenite=warn,tungstenite=warn",
        )
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
                .with_writer(file_writer),
        )
        .init();

    ensure_database_exists(&config).await?;

    let pg_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.postgres_url)
        .await?;

    MIGRATOR.run(&pg_pool).await?;

    let redis_cfg = deadpool_redis::Config::from_url(config.dragonfly_url.clone());
    let redis_pool = redis_cfg.create_pool(Some(Runtime::Tokio1))?;
    let token_manager = Arc::new(TokenManager::new(
        &config.paseto_local_key,
        config.access_token_ttl_minutes,
        config.refresh_token_ttl_days,
    ));
    let crypto_manager = Arc::new(CryptoManager::new(&config.xchacha20_key));
    let probe = crypto_manager.encrypt_string("haven-crypto-probe", Some(b"startup"))?;
    let probe_plain = crypto_manager.decrypt_to_string(&probe, Some(b"startup"))?;
    if probe_plain != "haven-crypto-probe" {
        return Err("xchacha20 startup self-test failed".into());
    }

    let rate_limiter = Arc::new(SimpleRateLimiter::new(
        config.rate_limit_requests_per_minute,
        Duration::from_secs(60),
    ));
    let (realtime_tx, _) = broadcast::channel(512);

    let state = AppState {
        pg_pool,
        redis_pool,
        dragonfly_url: config.dragonfly_url.clone(),
        token_manager,
        crypto_manager,
        rate_limiter,
        realtime_tx,
        avatar_storage_dir: config.avatar_storage_dir.clone(),
    };

    RealtimeService::new(state.clone()).spawn_fanout_bridge();

    let cors_layer = if config.cors_allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
            ])
            .allow_origin(Any)
    } else {
        let origins = config
            .cors_allowed_origins
            .iter()
            .filter_map(|origin| origin.parse::<axum::http::HeaderValue>().ok())
            .collect::<Vec<_>>();

        CorsLayer::new()
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
            ])
            .allow_origin(origins)
    };

    let api_router =
        routes::router().route_layer(from_fn_with_state(state.clone(), rate_limit_middleware));

    let app = Router::new()
        .route("/", get(|| async { "haven-backend" }))
        .nest("/api/v1", api_router)
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(config.request_body_limit_bytes))
        .layer(cors_layer)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .level(Level::INFO)
                        .include_headers(false),
                )
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
                .on_failure(DefaultOnFailure::new().level(Level::ERROR)),
        );

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!(
        log_file = %config.backend_log_file,
        "backend event logging enabled"
    );
    info!("haven-backend listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
