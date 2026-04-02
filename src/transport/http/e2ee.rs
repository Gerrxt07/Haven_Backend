use crate::{
    domain::e2ee::{ClaimPrekeyRequest, UploadKeyBundleRequest},
    error::AppError,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::{Path, State},
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
    State(state): State<AppState>,
    Json(payload): Json<UploadKeyBundleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let service = ServiceFactory::new(state).e2ee();
    service.upload_key_bundle(payload).await?;
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
    State(state): State<AppState>,
    Json(payload): Json<ClaimPrekeyRequest>,
) -> Result<Json<crate::domain::e2ee::KeyBundleWithPrekey>, AppError> {
    let service = ServiceFactory::new(state).e2ee();
    let bundle = service.claim_prekey_bundle(payload).await?;
    Ok(Json(bundle))
}
