use crate::{
    auth::{generate_id, hash_password, sha256_hex, verify_password, AuthTokens},
    domain::auth::{AuthUser, AuthUserResponse, LoginRequest, RefreshRequest, RegisterRequest},
    error::AppError,
    repository::auth_repository,
    state::AppState,
};
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use validator::Validate;

#[derive(Clone)]
pub struct AuthService {
    state: AppState,
}

impl AuthService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn register(&self, payload: RegisterRequest) -> Result<AuthUserResponse, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let password_hash = hash_password(&payload.password)?;
        let user_id = generate_id();

        let user = auth_repository::insert_user_for_registration(
            &self.state.pg_pool,
            auth_repository::NewRegistrationUser {
                user_id,
                username: payload.username.trim().to_lowercase(),
                display_name: payload.display_name.trim().to_string(),
                email: payload.email.trim().to_lowercase(),
                password_hash,
                date_of_birth: payload.date_of_birth,
                locale: payload.locale.trim().to_lowercase(),
            },
        )
        .await?;

        tracing::info!(
            event = "auth.register",
            user_id = user.id,
            email = user.email,
            "user registered"
        );
        Ok(user)
    }

    pub async fn login(&self, payload: LoginRequest) -> Result<AuthTokens, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let user = auth_repository::find_user_auth_by_email(
            &self.state.pg_pool,
            &payload.email.trim().to_lowercase(),
        )
        .await?
        .ok_or(AppError::Unauthorized)?;

        if user.account_status != "active" {
            tracing::warn!(
                event = "auth.login.blocked",
                user_id = user.id,
                status = user.account_status,
                "blocked login due to account status"
            );
            return Err(AppError::Forbidden);
        }

        if !verify_password(&user.password_hash, &payload.password) {
            tracing::warn!(
                event = "auth.login.failed",
                email = payload.email,
                "invalid password"
            );
            return Err(AppError::Unauthorized);
        }

        let session_id = generate_id();
        let tokens =
            self.state
                .token_manager
                .issue_tokens(user.id, session_id, user.token_version)?;

        let refresh_hash = sha256_hex(&tokens.refresh_token);
        let refresh_expires =
            Utc::now() + Duration::days(self.state.token_manager.refresh_ttl_days());

        auth_repository::insert_auth_session(
            &self.state.pg_pool,
            session_id,
            user.id,
            refresh_hash,
            refresh_expires,
            user.token_version,
        )
        .await?;

        auth_repository::update_last_login(&self.state.pg_pool, user.id).await?;

        tracing::info!(
            event = "auth.login",
            user_id = user.id,
            session_id,
            "login successful"
        );
        Ok(tokens)
    }

    pub async fn refresh(&self, payload: RefreshRequest) -> Result<AuthTokens, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let claims = self
            .state
            .token_manager
            .parse_and_validate(&payload.refresh_token, "refresh")?;

        let session =
            auth_repository::find_session(&self.state.pg_pool, claims.session_id, claims.user_id)
                .await?
                .ok_or(AppError::Unauthorized)?;

        if session.revoked_at.is_some() || session.expires_at < Utc::now() {
            return Err(AppError::Unauthorized);
        }

        if session.token_version != claims.token_version {
            return Err(AppError::Unauthorized);
        }

        let incoming_hash = sha256_hex(&payload.refresh_token);
        if session.refresh_token_hash != incoming_hash {
            return Err(AppError::Unauthorized);
        }

        let user =
            auth_repository::find_user_auth_by_id(&self.state.pg_pool, claims.user_id).await?;

        if user.account_status != "active" {
            return Err(AppError::Forbidden);
        }

        let new_session_id = generate_id();
        let tokens =
            self.state
                .token_manager
                .issue_tokens(user.id, new_session_id, user.token_version)?;

        let new_refresh_hash = sha256_hex(&tokens.refresh_token);
        let new_refresh_expires =
            Utc::now() + Duration::days(self.state.token_manager.refresh_ttl_days());

        let mut tx = auth_repository::begin_tx(&self.state.pg_pool).await?;
        auth_repository::revoke_session(&mut tx, session.id).await?;
        auth_repository::insert_auth_session_in_tx(
            &mut tx,
            new_session_id,
            user.id,
            new_refresh_hash,
            new_refresh_expires,
            user.token_version,
        )
        .await?;
        auth_repository::commit_tx(tx).await?;

        tracing::info!(
            event = "auth.refresh",
            user_id = user.id,
            old_session = session.id,
            new_session = new_session_id,
            "token refresh successful"
        );
        Ok(tokens)
    }

    pub async fn me(&self, headers: &HeaderMap) -> Result<AuthUserResponse, AppError> {
        let user = self.authenticate_from_headers(headers).await?;

        auth_repository::find_current_user(&self.state.pg_pool, user.id)
            .await?
            .ok_or(AppError::Unauthorized)
    }

    async fn authenticate_from_headers(&self, headers: &HeaderMap) -> Result<AuthUser, AppError> {
        let bearer = extract_bearer(headers)?;
        let claims = self
            .state
            .token_manager
            .parse_and_validate(&bearer, "access")?;

        let status_row =
            auth_repository::find_status_and_token_version(&self.state.pg_pool, claims.user_id)
                .await?
                .ok_or(AppError::Unauthorized)?;

        if status_row.0 != "active" {
            return Err(AppError::Forbidden);
        }

        if status_row.1 != claims.token_version {
            return Err(AppError::Unauthorized);
        }

        Ok(AuthUser { id: claims.user_id })
    }
}

fn extract_bearer(headers: &HeaderMap) -> Result<String, AppError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized)?;

    Ok(token.to_string())
}
