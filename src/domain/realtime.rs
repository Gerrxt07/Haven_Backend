use crate::error::AppError;
use chrono::Utc;
use serde::{Deserialize, Serialize};

pub const MAX_WS_MESSAGES_PER_SECOND: u32 = 5;
pub const WS_MESSAGE_RATE_LIMIT_WINDOW_SECONDS: u64 = 1;

pub struct E2eePayloadFields<'a> {
    pub ciphertext: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub aad: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeEvent {
    pub event_type: String,
    pub user_id: Option<i64>,
    pub channel: Option<String>,
    pub payload: serde_json::Value,
    pub ts: i64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientRealtimeMessage {
    Authenticate {
        token: String,
    },
    Join {
        channel: String,
    },
    Broadcast {
        channel: String,
        payload: serde_json::Value,
    },
    Presence {
        status: String,
    },
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

pub fn websocket_message_rate_limit_key(session_id: &str) -> String {
    format!("ws:msg:{session_id}")
}

pub fn extract_e2ee_payload_fields(
    payload: &serde_json::Value,
) -> Result<E2eePayloadFields<'_>, AppError> {
    let Some(payload_obj) = payload.as_object() else {
        return Ok(E2eePayloadFields {
            ciphertext: None,
            nonce: None,
            aad: None,
        });
    };

    Ok(E2eePayloadFields {
        ciphertext: json_string_field(payload_obj, "ciphertext")?,
        nonce: json_string_field(payload_obj, "nonce")?,
        aad: json_string_field(payload_obj, "aad")?,
    })
}

fn json_string_field<'a>(
    payload: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<&'a str>, AppError> {
    match payload.get(field) {
        Some(serde_json::Value::String(value)) => Ok(Some(value.as_str())),
        Some(serde_json::Value::Null) | None => Ok(None),
        Some(_) => Err(AppError::BadRequest(format!("{field} must be a string"))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_e2ee_payload_fields, websocket_message_rate_limit_key, ClientRealtimeMessage,
    };

    #[test]
    fn authenticate_message_deserializes() {
        let message: ClientRealtimeMessage =
            serde_json::from_str(r#"{"type":"authenticate","token":"token-123"}"#)
                .expect("authenticate message should parse");

        assert!(matches!(
            message,
            ClientRealtimeMessage::Authenticate { token } if token == "token-123"
        ));
    }

    #[test]
    fn join_rejects_client_supplied_user_id() {
        let err = serde_json::from_str::<ClientRealtimeMessage>(
            r#"{"type":"join","channel":"1","user_id":42}"#,
        )
        .expect_err("join should reject user_id");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn extracts_optional_e2ee_fields_from_payload() {
        let payload = serde_json::json!({
            "ciphertext": "abc",
            "nonce": "def",
            "aad": "ghi"
        });

        let fields = extract_e2ee_payload_fields(&payload).expect("fields should parse");
        assert_eq!(fields.ciphertext, Some("abc"));
        assert_eq!(fields.nonce, Some("def"));
        assert_eq!(fields.aad, Some("ghi"));
    }

    #[test]
    fn websocket_message_rate_limit_key_is_namespaced() {
        assert_eq!(
            websocket_message_rate_limit_key("session-1"),
            "ws:msg:session-1"
        );
    }
}
