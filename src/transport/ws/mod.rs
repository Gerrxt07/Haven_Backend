use crate::{
    auth::generate_id,
    domain::{
        e2ee::validate_e2ee_payload_size,
        realtime::{
            extract_e2ee_payload_fields, websocket_message_rate_limit_key, ClientRealtimeMessage,
            RealtimeEvent, MAX_WS_MESSAGES_PER_SECOND, WS_MESSAGE_RATE_LIMIT_WINDOW_SECONDS,
        },
    },
    error::AppError,
    repository::chat_repository,
    security::SimpleRateLimiter,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Default)]
struct WsConnectionState {
    actor_user_id: Option<i64>,
    subscribed_channels: HashSet<String>,
}

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

fn is_friend_request_event_relevant_for_actor(event: &RealtimeEvent, actor_user_id: i64) -> bool {
    let Some(request) = event.payload.get("request") else {
        return event.user_id == Some(actor_user_id);
    };
    let Some(request_obj) = request.as_object() else {
        return event.user_id == Some(actor_user_id);
    };

    let from_user_id = request_obj.get("from_user_id").and_then(|v| v.as_i64());
    let to_user_id = request_obj.get("to_user_id").and_then(|v| v.as_i64());
    matches!(from_user_id, Some(id) if id == actor_user_id)
        || matches!(to_user_id, Some(id) if id == actor_user_id)
}

fn should_send_event(event: &RealtimeEvent, connection: &WsConnectionState) -> bool {
    if event.event_type == "client_joined" || event.event_type == "join" {
        return false;
    }

    if let Some(channel) = &event.channel {
        return connection.subscribed_channels.contains(channel);
    }

    if event.event_type.starts_with("friend_request_") {
        let Some(actor_user_id) = connection.actor_user_id else {
            return false;
        };
        return is_friend_request_event_relevant_for_actor(event, actor_user_id);
    }

    true
}

async fn user_can_join_channel(state: &AppState, user_id: i64, channel: &str) -> bool {
    if let Some(dm_thread) = channel.strip_prefix("dm:") {
        let Ok(thread_id) = dm_thread.parse::<i64>() else {
            return false;
        };
        if thread_id <= 0 {
            return false;
        }

        return chat_repository::is_dm_participant(&state.pg_pool, thread_id, user_id)
            .await
            .unwrap_or(false);
    }

    let Ok(channel_id) = channel.parse::<i64>() else {
        return true;
    };

    if channel_id <= 0 {
        return false;
    }

    chat_repository::is_channel_member(&state.pg_pool, channel_id, user_id)
        .await
        .unwrap_or(false)
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let service_factory = ServiceFactory::new(state.clone());
    let service = service_factory.realtime();
    let mut rx = service.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let ws_session_id = format!("{}", generate_id());
    let connection_state = Arc::new(RwLock::new(WsConnectionState {
        actor_user_id: None,
        subscribed_channels: HashSet::new(),
    }));
    let send_connection_state = Arc::clone(&connection_state);
    let (control_tx, mut control_rx) = mpsc::channel::<Message>(16);

    let mut send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(message) = control_rx.recv() => {
                    if sender.send(message).await.is_err() {
                        break;
                    }
                }
                event_result = rx.recv() => {
                    match event_result {
                        Ok(event) => {
                    let should_send = {
                        let state = send_connection_state.read().await;
                        should_send_event(&event, &state)
                    };
                    if !should_send {
                        continue;
                    }

                    let payload = match simd_json::to_string(&event) {
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
            }
        }
    });

    let recv_state = state.clone();
    let recv_state_for_membership = state.clone();
    let recv_state_for_auth = state.clone();
    let recv_connection_state = Arc::clone(&connection_state);
    let recv_ws_session_id = ws_session_id.clone();
    let recv_control_tx = control_tx.clone();
    let mut recv_task = tokio::spawn(async move {
        let recv_service = ServiceFactory::new(recv_state).realtime();
        let auth_service = ServiceFactory::new(recv_state_for_auth).auth();
        let message_limiter = SimpleRateLimiter::new(
            MAX_WS_MESSAGES_PER_SECOND,
            std::time::Duration::from_secs(WS_MESSAGE_RATE_LIMIT_WINDOW_SECONDS),
        );
        let message_limit_key = websocket_message_rate_limit_key(&recv_ws_session_id);

        while let Some(Ok(message)) = receiver.next().await {
            match message {
                Message::Text(text) => {
                    if !message_limiter.allow(&message_limit_key).await {
                        continue;
                    }

                    let mut bytes = text.as_bytes().to_vec();
                    let parsed: Result<ClientRealtimeMessage, _> =
                        simd_json::serde::from_slice(&mut bytes);
                    let Ok(client_msg) = parsed else {
                        continue;
                    };
                    match client_msg {
                        ClientRealtimeMessage::Authenticate { token } => {
                            let Ok(actor_user_id) = auth_service
                                .authenticate_access_token(&token)
                                .await
                                .map(|user| user.id)
                            else {
                                continue;
                            };

                            let mut state = recv_connection_state.write().await;
                            match state.actor_user_id {
                                Some(existing) if existing != actor_user_id => continue,
                                Some(_) => {}
                                None => {
                                    state.actor_user_id = Some(actor_user_id);
                                }
                            }
                        }
                        ClientRealtimeMessage::Join { channel } => {
                            let actor_user_id = {
                                let mut state = recv_connection_state.write().await;
                                let Some(actor_user_id) = state.actor_user_id else {
                                    continue;
                                };
                                if !state.subscribed_channels.contains(&channel) {
                                    state.subscribed_channels.insert(channel.clone());
                                }
                                actor_user_id
                            };

                            if !user_can_join_channel(
                                &recv_state_for_membership,
                                actor_user_id,
                                &channel,
                            )
                            .await
                            {
                                let mut state = recv_connection_state.write().await;
                                state.subscribed_channels.remove(&channel);
                                continue;
                            }

                            let _ = recv_service
                                .cache_ws_session(&recv_ws_session_id, actor_user_id)
                                .await;
                            let _ = recv_service.set_presence(actor_user_id, "online").await;
                        }
                        ClientRealtimeMessage::Broadcast { channel, payload } => {
                            let actor_user_id = {
                                let state = recv_connection_state.read().await;
                                match state.actor_user_id {
                                    Some(actor_user_id)
                                        if state.subscribed_channels.contains(&channel) =>
                                    {
                                        actor_user_id
                                    }
                                    _ => continue,
                                }
                            };

                            let fields = match extract_e2ee_payload_fields(&payload) {
                                Ok(fields) => fields,
                                Err(_) => continue,
                            };
                            if validate_e2ee_payload_size(
                                fields.ciphertext,
                                fields.nonce,
                                fields.aad,
                            )
                            .is_err()
                            {
                                continue;
                            }

                            let event = RealtimeEvent::new(
                                "broadcast",
                                Some(actor_user_id),
                                Some(channel),
                                payload,
                            );
                            let _ = recv_service.publish_with_fanout(event).await;
                        }
                        ClientRealtimeMessage::Presence { status } => {
                            let Some(actor_user_id) =
                                ({ recv_connection_state.read().await.actor_user_id })
                            else {
                                continue;
                            };

                            let _ = recv_service.set_presence(actor_user_id, &status).await;
                            let event = RealtimeEvent::new(
                                "presence",
                                Some(actor_user_id),
                                None,
                                serde_json::json!({ "status": status }),
                            );
                            let _ = recv_service.publish_with_fanout(event).await;
                        }
                        ClientRealtimeMessage::Ping => {
                            let event = RealtimeEvent::new(
                                "pong",
                                None,
                                None,
                                serde_json::json!({ "status": "ok" }),
                            );
                            if let Ok(payload) = simd_json::to_string(&event) {
                                let _ = recv_control_tx.send(Message::Text(payload.into())).await;
                            }
                        }
                    }
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) | Message::Binary(_) => {}
            }
        }

        let actor_user_id = { recv_connection_state.read().await.actor_user_id };
        if let Some(actor_user_id) = actor_user_id {
            let _ = recv_service.set_presence(actor_user_id, "offline").await;
        }

        let _ = recv_service.remove_ws_session(&recv_ws_session_id).await;
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
