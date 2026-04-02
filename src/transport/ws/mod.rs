use crate::{
    auth::generate_id,
    domain::realtime::{ClientRealtimeMessage, RealtimeEvent},
    error::AppError,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/realtime/ws", get(ws_upgrade))
        .route("/ws", get(ws_upgrade))
}

async fn ws_upgrade(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    Ok(ws.on_upgrade(move |socket| handle_socket(state, socket)))
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let service_factory = ServiceFactory::new(state.clone());
    let service = service_factory.realtime();
    let mut rx = service.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let ws_session_id = format!("{}", generate_id());

    let joined = RealtimeEvent::new("client_joined", None, None, serde_json::json!({ "ok": true }));
    let _ = service.publish_with_fanout(joined).await;

    let mut send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let payload = match serde_json::to_string(&event) {
                        Ok(json) => json,
                        Err(_) => continue,
                    };
                    if sender.send(Message::Text(payload.into())).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let recv_state = state.clone();
    let mut recv_task = tokio::spawn(async move {
        let recv_service = ServiceFactory::new(recv_state).realtime();

        while let Some(Ok(message)) = receiver.next().await {
            match message {
                Message::Text(text) => {
                    let parsed: Result<ClientRealtimeMessage, _> = serde_json::from_str(&text);
                    let Ok(client_msg) = parsed else {
                        continue;
                    };

                    let event = match client_msg {
                        ClientRealtimeMessage::Join { channel, user_id } => RealtimeEvent::new(
                            "join",
                            user_id,
                            Some(channel),
                            serde_json::json!({ "joined": true }),
                        ),
                        ClientRealtimeMessage::Broadcast {
                            channel,
                            user_id,
                            payload,
                        } => RealtimeEvent::new("broadcast", user_id, Some(channel), payload),
                        ClientRealtimeMessage::Presence { user_id, status } => RealtimeEvent::new(
                            "presence",
                            Some(user_id),
                            None,
                            serde_json::json!({ "status": status }),
                        ),
                        ClientRealtimeMessage::Ping => RealtimeEvent::new(
                            "pong",
                            None,
                            None,
                            serde_json::json!({ "pong": true }),
                        ),
                    };

                    if event.event_type == "join" {
                        if let Some(user_id) = event.user_id {
                            let _ = recv_service.cache_ws_session(&ws_session_id, user_id).await;
                            let _ = recv_service.set_presence(user_id, "online").await;
                        }
                    }

                    if event.event_type == "presence" {
                        if let Some(user_id) = event.user_id {
                            let status = event
                                .payload
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("online");
                            let _ = recv_service.set_presence(user_id, status).await;
                        }
                    }

                    let _ = recv_service.publish_with_fanout(event).await;
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) | Message::Binary(_) => {}
            }
        }

        let _ = recv_service.remove_ws_session(&ws_session_id).await;
    });

    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        }
        _ = &mut recv_task => {
            send_task.abort();
        }
    }
}
