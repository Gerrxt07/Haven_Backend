use crate::{
    domain::auth::{
        EmailVerificationConfirmRequest, EmailVerificationRequest, LoginChallengeRequest,
        LoginVerifyRequest, RefreshRequest, RegisterRequest, StatusResponse,
        TwoFactorConfirmRequest, TwoFactorDisableRequest, TwoFactorSetupResponse,
    },
    error::AppError,
    service::ServiceFactory,
    state::AppState,
};
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login/challenge", post(login_challenge))
        .route("/auth/login/verify", post(login_verify))
        .route("/auth/refresh", post(refresh))
        .route("/auth/me", get(me))
        .route(
            "/auth/email/verification/request",
            post(request_email_verification),
        )
        .route(
            "/auth/email/verification/confirm",
            post(confirm_email_verification),
        )
        .route("/auth/2fa/setup", post(setup_two_factor))
        .route("/auth/2fa/confirm", post(confirm_two_factor))
        .route("/auth/2fa/disable", post(disable_two_factor))
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<crate::domain::auth::AuthUserResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let user = service.register(payload).await?;
    Ok(Json(user))
}

async fn login_challenge(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<LoginChallengeRequest>,
) -> Result<Json<crate::domain::auth::LoginChallengeResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let (_, response) = service.login_challenge(&headers, payload).await?;
    Ok(Json(response))
}

async fn login_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginVerifyRequest>,
) -> Result<Json<crate::domain::auth::LoginVerifyResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();

    // Extract challenge_id from header (set by client)
    let challenge_id = headers
        .get("x-srp-challenge-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::BadRequest("Missing x-srp-challenge-id header".to_string()))?;

    let response = service
        .login_verify(&headers, challenge_id, payload)
        .await?;
    Ok(Json(response))
}

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<crate::auth::AuthTokens>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let tokens = service.refresh(payload).await?;
    Ok(Json(tokens))
}

async fn me(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<crate::domain::auth::AuthUserResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let current = service.me(&headers).await?;
    Ok(Json(current))
}

async fn request_email_verification(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<EmailVerificationRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let status = service
        .request_email_verification(&headers, payload)
        .await?;
    Ok(Json(status))
}

async fn confirm_email_verification(
    State(state): State<AppState>,
    Json(payload): Json<EmailVerificationConfirmRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let status = service.confirm_email_verification(payload).await?;
    Ok(Json(status))
}

async fn setup_two_factor(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<TwoFactorSetupResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let response = service.setup_two_factor(&headers).await?;
    Ok(Json(response))
}

async fn confirm_two_factor(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<TwoFactorConfirmRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let status = service.confirm_two_factor(&headers, payload).await?;
    Ok(Json(status))
}

async fn disable_two_factor(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<TwoFactorDisableRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    let service = ServiceFactory::new(state).auth();
    let status = service.disable_two_factor(&headers, payload).await?;
    Ok(Json(status))
}
