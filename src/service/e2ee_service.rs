use crate::{
    domain::e2ee::{
        ClaimPrekeyRequest, KeyBundleWithPrekey, PublicKeyBundle, UploadKeyBundleRequest,
    },
    error::AppError,
    repository::e2ee_repository,
    state::AppState,
};
use validator::Validate;

#[derive(Clone)]
pub struct E2eeService {
    state: AppState,
}

impl E2eeService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn upload_key_bundle(&self, payload: UploadKeyBundleRequest) -> Result<(), AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if payload.user_id <= 0 || payload.signed_prekey_id <= 0 {
            return Err(AppError::Validation(
                "invalid user_id or signed_prekey_id".to_string(),
            ));
        }

        if payload.one_time_prekeys.is_empty() {
            return Err(AppError::Validation(
                "at least one one_time_prekey is required".to_string(),
            ));
        }

        if !e2ee_repository::user_exists(&self.state.pg_pool, payload.user_id).await? {
            return Err(AppError::BadRequest("user not found".to_string()));
        }

        e2ee_repository::upsert_key_bundle(&self.state.pg_pool, &payload).await
    }

    pub async fn get_public_bundle(&self, user_id: i64) -> Result<PublicKeyBundle, AppError> {
        if user_id <= 0 {
            return Err(AppError::Validation("user_id must be > 0".to_string()));
        }

        e2ee_repository::get_public_bundle(&self.state.pg_pool, user_id)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn claim_prekey_bundle(
        &self,
        payload: ClaimPrekeyRequest,
    ) -> Result<KeyBundleWithPrekey, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if payload.requester_user_id <= 0 || payload.target_user_id <= 0 {
            return Err(AppError::Validation(
                "invalid requester_user_id or target_user_id".to_string(),
            ));
        }

        if payload.requester_user_id == payload.target_user_id {
            return Err(AppError::BadRequest(
                "requester_user_id and target_user_id must differ".to_string(),
            ));
        }

        if !e2ee_repository::user_exists(&self.state.pg_pool, payload.requester_user_id).await? {
            return Err(AppError::BadRequest("requester user not found".to_string()));
        }

        e2ee_repository::claim_prekey_bundle(&self.state.pg_pool, payload.target_user_id)
            .await?
            .ok_or(AppError::NotFound)
    }
}
