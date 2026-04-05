use crate::{
    domain::chat::{
        CreateChannelDirectRequest, CreateChannelRequest, CreateMessageDirectRequest,
        CreateMessageRequest, CreateServerRequest, PaginationQuery,
    },
    error::AppError,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use std::collections::HashMap;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/servers", post(create_server))
        .route("/channels", post(create_channel_direct))
        .route("/messages", post(create_message_direct))
        .route(
            "/servers/{server_id}/channels",
            post(create_channel).get(list_channels),
        )
        .route(
            "/channels/{channel_id}/messages",
            post(create_message).get(list_messages),
        )
}

async fn create_server(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<CreateServerRequest>,
) -> Result<Json<crate::domain::chat::Server>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let server = factory.chat().create_server(actor.id, payload).await?;
    Ok(Json(server))
}

async fn create_channel(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<crate::domain::chat::Channel>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let channel = factory
        .chat()
        .create_channel(actor.id, server_id, payload)
        .await?;
    Ok(Json(channel))
}

async fn list_channels(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<Vec<crate::domain::chat::Channel>>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let channels = factory
        .chat()
        .list_channels(actor.id, server_id, query)
        .await?;
    Ok(Json(channels))
}

async fn create_message(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(channel_id): Path<i64>,
    Json(payload): Json<CreateMessageRequest>,
) -> Result<Json<crate::domain::chat::Message>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let message = factory
        .chat()
        .create_message(actor.id, channel_id, payload)
        .await?;
    Ok(Json(message))
}

async fn list_messages(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(channel_id): Path<i64>,
    Query(raw): Query<HashMap<String, String>>,
) -> Result<Json<Vec<crate::domain::chat::Message>>, AppError> {
    for key in raw.keys() {
        if key != "before" && key != "limit" {
            return Err(AppError::BadRequest(
                "only cursor pagination is supported: use before and limit".to_string(),
            ));
        }
    }

    let before = match raw.get("before") {
        Some(v) => Some(
            v.parse::<i64>()
                .map_err(|_| AppError::Validation("before must be an integer".to_string()))?,
        ),
        None => None,
    };

    let limit = match raw.get("limit") {
        Some(v) => Some(
            v.parse::<i64>()
                .map_err(|_| AppError::Validation("limit must be an integer".to_string()))?,
        ),
        None => None,
    };

    let query = PaginationQuery { before, limit };

    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let messages = factory
        .chat()
        .list_messages(actor.id, channel_id, query)
        .await?;
    Ok(Json(messages))
}

async fn create_channel_direct(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<CreateChannelDirectRequest>,
) -> Result<Json<crate::domain::chat::Channel>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let channel = factory
        .chat()
        .create_channel_direct(actor.id, payload)
        .await?;
    Ok(Json(channel))
}

async fn create_message_direct(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<CreateMessageDirectRequest>,
) -> Result<Json<crate::domain::chat::Message>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let message = factory
        .chat()
        .create_message_direct(actor.id, payload)
        .await?;
    Ok(Json(message))
}
