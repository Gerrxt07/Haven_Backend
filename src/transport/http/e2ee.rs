use crate::{
    domain::e2ee::{ClaimPrekeyRequest, UploadKeyBundleRequest},
    error::AppError,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/e2ee/keys/bundle", post(upload_key_bundle))
        .route("/e2ee/keys/bundle/{user_id}", get(get_public_bundle))
        .route("/e2ee/keys/claim", post(claim_prekey_bundle))
}

async fn upload_key_bundle(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<UploadKeyBundleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    factory.e2ee().upload_key_bundle(actor.id, payload).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_public_bundle(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
) -> Result<Json<crate::domain::e2ee::PublicKeyBundle>, AppError> {
    let service = ServiceFactory::new(state).e2ee();
    let bundle = service.get_public_bundle(user_id).await?;
    Ok(Json(bundle))
}

async fn claim_prekey_bundle(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<ClaimPrekeyRequest>,
) -> Result<Json<crate::domain::e2ee::KeyBundleWithPrekey>, AppError> {
    let factory = ServiceFactory::new(state);
    let actor = factory.auth().authenticate_request(&headers).await?;
    let bundle = factory
        .e2ee()
        .claim_prekey_bundle(actor.id, payload)
        .await?;
    Ok(Json(bundle))
}
