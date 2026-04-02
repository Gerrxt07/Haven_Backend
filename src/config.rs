use std::env;

pub struct Config {
    pub host: String,
    pub port: u16,
    pub postgres_admin_url: String,
    pub postgres_db: String,
    pub postgres_url: String,
    pub dragonfly_url: String,
    pub paseto_local_key: String,
    pub xchacha20_key: String,
    pub cors_allowed_origins: Vec<String>,
    pub request_body_limit_bytes: usize,
    pub rate_limit_requests_per_minute: u32,
    pub access_token_ttl_minutes: i64,
    pub refresh_token_ttl_days: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let host = env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("APP_PORT")
            .unwrap_or_else(|_| "8086".to_string())
            .parse::<u16>()?;

        let postgres_db = env::var("POSTGRES_DB").unwrap_or_else(|_| "haven".to_string());
        let postgres_admin_url = env::var("POSTGRES_ADMIN_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432/postgres".to_string());

        let postgres_url = env::var("POSTGRES_URL")
            .unwrap_or_else(|_| format!("postgres://postgres:postgres@127.0.0.1:5432/{postgres_db}"));
        let dragonfly_url =
            env::var("DRAGONFLY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let paseto_local_key = env::var("PASETO_LOCAL_KEY")
            .unwrap_or_else(|_| "haven-change-me-32-byte-secret-key!".to_string());
        let xchacha20_key = env::var("XCHACHA20_KEY")
            .unwrap_or_else(|_| "haven-change-me-xchacha20-key".to_string());
        let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5173".to_string())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let request_body_limit_bytes = env::var("REQUEST_BODY_LIMIT_BYTES")
            .unwrap_or_else(|_| "1048576".to_string())
            .parse::<usize>()?;
        let rate_limit_requests_per_minute = env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
            .unwrap_or_else(|_| "120".to_string())
            .parse::<u32>()?;
        let access_token_ttl_minutes = env::var("ACCESS_TOKEN_TTL_MINUTES")
            .unwrap_or_else(|_| "15".to_string())
            .parse::<i64>()?;
        let refresh_token_ttl_days = env::var("REFRESH_TOKEN_TTL_DAYS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<i64>()?;

        Ok(Self {
            host,
            port,
            postgres_admin_url,
            postgres_db,
            postgres_url,
            dragonfly_url,
            paseto_local_key,
            xchacha20_key,
            cors_allowed_origins,
            request_body_limit_bytes,
            rate_limit_requests_per_minute,
            access_token_ttl_minutes,
            refresh_token_ttl_days,
        })
    }
}
