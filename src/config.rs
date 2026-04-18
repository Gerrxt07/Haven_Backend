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
    pub avatar_storage_dir: String,
    pub backend_log_file: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_email: String,
    pub smtp_from_name: String,
    pub smtp_use_starttls: bool,
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

        let postgres_url = env::var("POSTGRES_URL").unwrap_or_else(|_| {
            format!("postgres://postgres:postgres@127.0.0.1:5432/{postgres_db}")
        });
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
            .unwrap_or_else(|_| "6291456".to_string())
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
        let avatar_storage_dir = env::var("AVATAR_STORAGE_DIR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "./storage/avatars".to_string());
        let backend_log_file = env::var("BACKEND_LOG_FILE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "./backend-events.log".to_string());

        let smtp_host = env::var("SMTP_HOST")?;
        let smtp_port = env::var("SMTP_PORT")
            .unwrap_or_else(|_| "587".to_string())
            .parse::<u16>()?;
        let smtp_username = env::var("SMTP_USERNAME")?;
        let smtp_password = env::var("SMTP_PASSWORD")?;
        let smtp_from_email = env::var("SMTP_FROM_EMAIL")?;
        let smtp_from_name = env::var("SMTP_FROM_NAME").unwrap_or_else(|_| "Haven".to_string());
        let smtp_use_starttls = env::var("SMTP_USE_STARTTLS")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()?;

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
            avatar_storage_dir,
            backend_log_file,
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_from_email,
            smtp_from_name,
            smtp_use_starttls,
        })
    }

    pub fn validate_security(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.paseto_local_key.contains("change-me") || self.paseto_local_key.len() < 32 {
            return Err("PASETO_LOCAL_KEY must be set to a strong secret (>=32 chars)".into());
        }

        if self.xchacha20_key.contains("change-me") || self.xchacha20_key.len() < 32 {
            return Err("XCHACHA20_KEY must be set to a strong secret (>=32 chars)".into());
        }

        Ok(())
    }
}
