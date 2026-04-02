use crate::{error::AppError, state::AppState};
use axum::{
    extract::State,
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};
use std::{collections::{HashMap, VecDeque}, sync::Arc, time::{Duration, Instant}};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct SimpleRateLimiter {
    max_requests: u32,
    window: Duration,
    entries: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl SimpleRateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut guard = self.entries.lock().await;
        let bucket = guard.entry(key.to_string()).or_insert_with(VecDeque::new);

        while let Some(front) = bucket.front() {
            if *front < cutoff {
                bucket.pop_front();
            } else {
                break;
            }
        }

        if bucket.len() as u32 >= self.max_requests {
            return false;
        }

        bucket.push_back(now);
        true
    }
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        return value.split(',').next().unwrap_or("unknown").trim().to_string();
    }

    if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return value.trim().to_string();
    }

    "unknown".to_string()
}

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let ip = extract_client_ip(request.headers());
    let path = request.uri().path().to_string();
    let key = format!("{ip}:{path}");

    if !state.rate_limiter.allow(&key).await {
        return Err(AppError::TooManyRequests);
    }

    Ok(next.run(request).await)
}
