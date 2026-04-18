use crate::{
    domain::friends::SendFriendRequest, error::AppError, service::ServiceFactory, state::AppState,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/friends", get(list_friends))
        .route("/friends/request", post(send_friend_request))
        .route("/friends/requests/incoming", get(list_incoming_requests))
        .route("/friends/requests/outgoing", get(list_outgoing_requests))
        .route(
            "/friends/requests/{request_id}/accept",
            post(accept_request),
        )
        .route(
            "/friends/requests/{request_id}/decline",
            post(decline_request),
        )
}

async fn send_friend_request(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<SendFriendRequest>,
) -> Result<Json<crate::domain::friends::FriendRequest>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let request = factory.friends().send_request(actor.id, payload).await?;
    Ok(Json(request))
}

async fn list_incoming_requests(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::domain::friends::FriendRequest>>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let requests = factory.friends().list_incoming(actor.id).await?;
    Ok(Json(requests))
}

async fn list_outgoing_requests(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::domain::friends::FriendRequest>>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let requests = factory.friends().list_outgoing(actor.id).await?;
    Ok(Json(requests))
}

async fn accept_request(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(request_id): Path<i64>,
) -> Result<Json<crate::domain::friends::FriendRequest>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let request = factory
        .friends()
        .accept_request(actor.id, request_id)
        .await?;
    Ok(Json(request))
}

async fn decline_request(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(request_id): Path<i64>,
) -> Result<Json<crate::domain::friends::FriendRequest>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let request = factory
        .friends()
        .decline_request(actor.id, request_id)
        .await?;
    Ok(Json(request))
}

async fn list_friends(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::domain::friends::Friend>>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let friends = factory.friends().list_friends(actor.id).await?;
    Ok(Json(friends))
}
