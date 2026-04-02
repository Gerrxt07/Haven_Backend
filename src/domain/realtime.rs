use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeEvent {
    pub event_type: String,
    pub user_id: Option<i64>,
    pub channel: Option<String>,
    pub payload: serde_json::Value,
    pub ts: i64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientRealtimeMessage {
    Join { channel: String, user_id: Option<i64> },
    Broadcast { channel: String, user_id: Option<i64>, payload: serde_json::Value },
    Presence { user_id: i64, status: String },
    Ping,
}

impl RealtimeEvent {
    pub fn new(
        event_type: impl Into<String>,
        user_id: Option<i64>,
        channel: Option<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            user_id,
            channel,
            payload,
            ts: Utc::now().timestamp_millis(),
        }
    }
}
