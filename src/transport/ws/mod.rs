use crate::{
    auth::generate_id,
    domain::realtime::{ClientRealtimeMessage, RealtimeEvent},
    error::AppError,
    repository::chat_repository,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use std::{collections::HashSet, sync::Arc};
use tokio::sync::RwLock;

#[derive(Debug, Default, Deserialize)]
struct WsAuthQuery {
    access_token: Option<String>,
}

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
    Query(query): Query<WsAuthQuery>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    let actor_user_id = match query.access_token.as_deref() {
        Some(token) => Some(
            ServiceFactory::new(state.clone())
                .auth()
                .authenticate_access_token(token)
                .await?
                .id,
        ),
        None => None,
    };

    Ok(ws.on_upgrade(move |socket| handle_socket(state, socket, actor_user_id)))
}

fn bind_actor_user_id(bound: &mut Option<i64>, candidate: Option<i64>) -> Result<Option<i64>, ()> {
    match (*bound, candidate) {
        (Some(existing), Some(next)) if next > 0 && next != existing => Err(()),
        (Some(existing), _) => Ok(Some(existing)),
        (None, Some(next)) if next > 0 => {
            *bound = Some(next);
            Ok(Some(next))
        }
        (None, _) => Ok(None),
    }
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

async fn handle_socket(state: AppState, socket: WebSocket, actor_user_id: Option<i64>) {
    let service_factory = ServiceFactory::new(state.clone());
    let service = service_factory.realtime();
    let mut rx = service.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let ws_session_id = format!("{}", generate_id());
    let connection_state = Arc::new(RwLock::new(WsConnectionState {
        actor_user_id,
        subscribed_channels: HashSet::new(),
    }));
    let send_connection_state = Arc::clone(&connection_state);

    let mut send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
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
    });

    let recv_state = state.clone();
    let recv_state_for_membership = state.clone();
    let recv_connection_state = Arc::clone(&connection_state);
    let recv_ws_session_id = ws_session_id.clone();
    let mut recv_task = tokio::spawn(async move {
        let recv_service = ServiceFactory::new(recv_state).realtime();

        while let Some(Ok(message)) = receiver.next().await {
            match message {
                Message::Text(text) => {
                    let mut bytes = text.as_bytes().to_vec();
                    let parsed: Result<ClientRealtimeMessage, _> =
                        simd_json::serde::from_slice(&mut bytes);
                    let Ok(client_msg) = parsed else {
                        continue;
                    };
                    match client_msg {
                        ClientRealtimeMessage::Join { channel, user_id } => {
                            let resolved_user_id = {
                                let mut state = recv_connection_state.write().await;
                                let resolved =
                                    bind_actor_user_id(&mut state.actor_user_id, user_id);
                                if resolved.is_err() {
                                    None
                                } else {
                                    state.subscribed_channels.insert(channel.clone());
                                    resolved.ok().flatten()
                                }
                            };

                            if resolved_user_id.is_none() && user_id.is_some() {
                                continue;
                            }

                            if let Some(actor_user_id) = resolved_user_id {
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
                        }
                        ClientRealtimeMessage::Broadcast {
                            channel,
                            user_id,
                            payload,
                        } => {
                            let (rejected, resolved_user_id) = {
                                let mut state = recv_connection_state.write().await;
                                if !state.subscribed_channels.contains(&channel) {
                                    (true, None)
                                } else {
                                    match bind_actor_user_id(&mut state.actor_user_id, user_id) {
                                        Ok(resolved) => (false, resolved),
                                        Err(()) => (true, None),
                                    }
                                }
                            };
                            if rejected {
                                continue;
                            }

                            let event = RealtimeEvent::new(
                                "broadcast",
                                resolved_user_id,
                                Some(channel),
                                payload,
                            );
                            let _ = recv_service.publish_with_fanout(event).await;
                        }
                        ClientRealtimeMessage::Presence { user_id, status } => {
                            let Some(actor_user_id) = ({
                                let mut state = recv_connection_state.write().await;
                                bind_actor_user_id(&mut state.actor_user_id, Some(user_id))
                                    .ok()
                                    .flatten()
                            }) else {
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
                            // Keep ping lightweight: this is only used as liveness heartbeat.
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
