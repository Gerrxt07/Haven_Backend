use crate::{
    domain::user::{CreateUserRequest, User},
    error::AppError,
    repository::user_repository,
    state::AppState,
};

#[derive(Clone)]
pub struct UserService {
    state: AppState,
}

impl UserService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn create_user(&self, payload: CreateUserRequest) -> Result<User, AppError> {
        if payload.username.trim().is_empty() {
            return Err(AppError::BadRequest("username is required".to_string()));
        }
        if payload.display_name.trim().is_empty() {
            return Err(AppError::BadRequest("display_name is required".to_string()));
        }
        if payload.email.trim().is_empty() {
            return Err(AppError::BadRequest("email is required".to_string()));
        }

        user_repository::create_user(&self.state.pg_pool, payload).await
    }

    pub async fn get_user(&self, id: i64) -> Result<User, AppError> {
        user_repository::get_user(&self.state.pg_pool, id)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn update_avatar_url(&self, user_id: i64, avatar_url: &str) -> Result<(), AppError> {
        user_repository::update_avatar_url(&self.state.pg_pool, user_id, avatar_url).await
    }
}
