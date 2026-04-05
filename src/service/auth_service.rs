use crate::{
    auth::{generate_id, hash_password, sha256_hex, verify_password, AuthTokens},
    domain::auth::{
        AuthUser, AuthUserResponse, EmailVerificationConfirmRequest, EmailVerificationRequest,
        LoginRequest, RefreshRequest, RegisterRequest, StatusResponse, TwoFactorConfirmRequest,
        TwoFactorDisableRequest, TwoFactorSetupResponse,
    },
    error::AppError,
    repository::auth_repository,
    state::AppState,
};
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use urlencoding::encode;
use validator::Validate;

type HmacSha1 = Hmac<Sha1>;

const EMAIL_VERIFICATION_TTL_MINUTES: i64 = 10;
const EMAIL_VERIFICATION_CODE_LENGTH: usize = 6;
const EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS: i64 = 60;
const TOTP_STEP_SECONDS: i64 = 30;
const TOTP_DIGITS: u32 = 6;
const TOTP_SETUP_TTL_MINUTES: i64 = 10;
const BACKUP_CODE_COUNT: usize = 10;
const BACKUP_CODE_LENGTH: usize = 10;

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

        let normalized_email = payload.email.trim().to_lowercase();

        let user = match auth_repository::find_user_auth_by_email(
            &self.state.pg_pool,
            &normalized_email,
        )
        .await?
        {
            Some(user) => user,
            None => {
                tracing::warn!(
                    event = "auth.login.failed",
                    email = normalized_email,
                    reason = "user_not_found",
                    "invalid credentials"
                );
                return Err(AppError::Unauthorized);
            }
        };

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

        if let Some(secret) = &user.totp_secret {
            match (
                payload.totp_code.as_deref(),
                payload.backup_code.as_deref(),
            ) {
                (Some(code), _) => {
                    if !verify_totp_code(secret, code)? {
                        tracing::warn!(
                            event = "auth.login.failed",
                            email = payload.email,
                            reason = "invalid_totp",
                            "invalid 2fa code"
                        );
                        return Err(AppError::Unauthorized);
                    }
                }
                (None, Some(backup_code)) => {
                    let current_codes = user.totp_backup_codes.clone().unwrap_or_default();
                    let updated_codes =
                        consume_backup_code(&current_codes, backup_code).ok_or_else(|| {
                            tracing::warn!(
                                event = "auth.login.failed",
                                email = payload.email,
                                reason = "invalid_backup_code",
                                "invalid backup code"
                            );
                            AppError::Unauthorized
                        })?;
                    auth_repository::update_backup_codes(
                        &self.state.pg_pool,
                        user.id,
                        updated_codes,
                    )
                    .await?;
                }
                (None, None) => {
                    return Err(AppError::TwoFactorRequired);
                }
            }
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

    pub async fn request_email_verification(
        &self,
        headers: &HeaderMap,
        payload: EmailVerificationRequest,
    ) -> Result<StatusResponse, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let normalized_email = payload.email.trim().to_lowercase();

        let ip = crate::security::extract_client_ip(headers);
        let ip_key = format!("email-verify:ip:{ip}");
        if !self.state.email_verify_ip_limiter.allow(&ip_key).await {
            return Err(AppError::TooManyRequests);
        }

        let email_key = format!("email-verify:email:{normalized_email}");
        if !self.state.email_verify_email_limiter.allow(&email_key).await {
            return Err(AppError::TooManyRequests);
        }

        let user = match auth_repository::find_user_email_status_by_email(
            &self.state.pg_pool,
            &normalized_email,
        )
        .await?
        {
            Some(user) => user,
            None => {
                return Ok(StatusResponse { status: "ok" });
            }
        };

        if user.email_verified {
            return Ok(StatusResponse { status: "ok" });
        }

        if let Some(latest) =
            auth_repository::find_latest_email_verification_code(&self.state.pg_pool, user.id)
                .await?
        {
            let cooldown_until =
                latest.created_at + Duration::seconds(EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS);
            if cooldown_until > Utc::now() {
                return Err(AppError::TooManyRequests);
            }
        }

        let code = generate_numeric_code(EMAIL_VERIFICATION_CODE_LENGTH);
        let code_hash = sha256_hex(&code);
        let expires_at = Utc::now() + Duration::minutes(EMAIL_VERIFICATION_TTL_MINUTES);

        auth_repository::delete_email_verification_codes(&self.state.pg_pool, user.id).await?;
        auth_repository::insert_email_verification_code(
            &self.state.pg_pool,
            generate_id(),
            user.id,
            code_hash,
            expires_at,
        )
        .await?;

        self.state
            .email_client
            .send_verification_code(&normalized_email, &code, EMAIL_VERIFICATION_TTL_MINUTES)
            .await?;

        Ok(StatusResponse { status: "ok" })
    }

    pub async fn confirm_email_verification(
        &self,
        payload: EmailVerificationConfirmRequest,
    ) -> Result<StatusResponse, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let normalized_email = payload.email.trim().to_lowercase();
        let user = auth_repository::find_user_email_status_by_email(
            &self.state.pg_pool,
            &normalized_email,
        )
        .await?
        .ok_or(AppError::Unauthorized)?;

        if user.email_verified {
            return Ok(StatusResponse { status: "ok" });
        }

        let latest_code =
            auth_repository::find_latest_email_verification_code(&self.state.pg_pool, user.id)
                .await?
                .ok_or_else(|| AppError::BadRequest("verification code not found".to_string()))?;

        if latest_code.consumed_at.is_some() || latest_code.expires_at < Utc::now() {
            return Err(AppError::BadRequest("verification code expired".to_string()));
        }

        let incoming_hash = sha256_hex(payload.code.trim());
        if incoming_hash != latest_code.code_hash {
            return Err(AppError::BadRequest("invalid verification code".to_string()));
        }

        auth_repository::mark_email_verification_code_consumed(
            &self.state.pg_pool,
            latest_code.id,
        )
        .await?;
        auth_repository::set_email_verified(&self.state.pg_pool, user.id).await?;

        Ok(StatusResponse { status: "verified" })
    }

    pub async fn setup_two_factor(
        &self,
        headers: &HeaderMap,
    ) -> Result<TwoFactorSetupResponse, AppError> {
        let user = self.authenticate_from_headers(headers).await?;
        let current =
            auth_repository::find_user_auth_by_id(&self.state.pg_pool, user.id).await?;

        if current.totp_secret.is_some() {
            return Err(AppError::Conflict("2fa already enabled".to_string()));
        }

        let secret = generate_totp_secret();
        let backup_codes = generate_backup_codes();
        let hashed_backup_codes = hash_backup_codes(&backup_codes);
        let expires_at = Utc::now() + Duration::minutes(TOTP_SETUP_TTL_MINUTES);

        auth_repository::upsert_totp_setup(
            &self.state.pg_pool,
            user.id,
            secret.clone(),
            hashed_backup_codes,
            expires_at,
        )
        .await?;

        let otpauth_url = build_otpauth_url(&secret, user.id);

        Ok(TwoFactorSetupResponse {
            secret,
            otpauth_url,
            backup_codes,
            expires_at,
        })
    }

    pub async fn confirm_two_factor(
        &self,
        headers: &HeaderMap,
        payload: TwoFactorConfirmRequest,
    ) -> Result<StatusResponse, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let user = self.authenticate_from_headers(headers).await?;
        let setup = auth_repository::find_totp_setup(&self.state.pg_pool, user.id)
            .await?
            .ok_or_else(|| AppError::BadRequest("2fa setup not found".to_string()))?;

        if setup.expires_at < Utc::now() {
            auth_repository::delete_totp_setup(&self.state.pg_pool, user.id).await?;
            return Err(AppError::BadRequest("2fa setup expired".to_string()));
        }

        if !verify_totp_code(&setup.secret, payload.code.trim())? {
            return Err(AppError::BadRequest("invalid 2fa code".to_string()));
        }

        auth_repository::set_user_totp(
            &self.state.pg_pool,
            user.id,
            setup.secret,
            setup.backup_codes,
        )
        .await?;
        auth_repository::delete_totp_setup(&self.state.pg_pool, user.id).await?;

        Ok(StatusResponse { status: "enabled" })
    }

    pub async fn disable_two_factor(
        &self,
        headers: &HeaderMap,
        payload: TwoFactorDisableRequest,
    ) -> Result<StatusResponse, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let user = self.authenticate_from_headers(headers).await?;
        let current =
            auth_repository::find_user_auth_by_id(&self.state.pg_pool, user.id).await?;

        let secret = current
            .totp_secret
            .ok_or_else(|| AppError::BadRequest("2fa not enabled".to_string()))?;

        let mut backup_codes = current.totp_backup_codes.clone().unwrap_or_default();

        let mut verified = false;
        if let Some(code) = payload.code.as_deref() {
            verified = verify_totp_code(&secret, code.trim())?;
        }

        if !verified {
            if let Some(backup_code) = payload.backup_code.as_deref() {
                if let Some(updated) = consume_backup_code(&backup_codes, backup_code) {
                    backup_codes = updated;
                    auth_repository::update_backup_codes(
                        &self.state.pg_pool,
                        user.id,
                        backup_codes,
                    )
                    .await?;
                    verified = true;
                }
            }
        }

        if !verified {
            return Err(AppError::Unauthorized);
        }

        auth_repository::clear_user_totp(&self.state.pg_pool, user.id).await?;
        Ok(StatusResponse { status: "disabled" })
    }

    pub async fn authenticate_request(&self, headers: &HeaderMap) -> Result<AuthUser, AppError> {
        self.authenticate_from_headers(headers).await
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

fn generate_numeric_code(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let max = 10_u32.pow(length as u32);
    let value = rng.next_u32() % max;
    format!("{:0width$}", value, width = length)
}

fn generate_totp_secret() -> String {
    let mut secret = [0_u8; 20];
    rand::thread_rng().fill_bytes(&mut secret);
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret)
}

fn build_otpauth_url(secret: &str, user_id: i64) -> String {
    let label = encode(&format!("Haven:{user_id}"));
    let issuer = encode("Haven");
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        label, secret, issuer, TOTP_DIGITS, TOTP_STEP_SECONDS
    )
}

fn generate_backup_codes() -> Vec<String> {
    let mut codes = Vec::with_capacity(BACKUP_CODE_COUNT);
    for _ in 0..BACKUP_CODE_COUNT {
        let mut code = String::with_capacity(BACKUP_CODE_LENGTH);
        let mut bytes = [0_u8; BACKUP_CODE_LENGTH];
        rand::thread_rng().fill_bytes(&mut bytes);
        for b in bytes.iter() {
            let val = b % 36;
            let ch = if val < 10 {
                (b'0' + val) as char
            } else {
                (b'a' + (val - 10)) as char
            };
            code.push(ch);
        }
        codes.push(code);
    }
    codes
}

fn hash_backup_codes(codes: &[String]) -> Vec<String> {
    codes.iter().map(|c| sha256_hex(c)).collect()
}

fn consume_backup_code(stored_hashes: &[String], provided: &str) -> Option<Vec<String>> {
    let incoming_hash = sha256_hex(provided.trim());
    if !stored_hashes.iter().any(|hash| hash == &incoming_hash) {
        return None;
    }
    let updated = stored_hashes
        .iter()
        .filter(|hash| *hash != &incoming_hash)
        .cloned()
        .collect::<Vec<_>>();
    Some(updated)
}

fn verify_totp_code(secret_base32: &str, code: &str) -> Result<bool, AppError> {
    let secret = base32::decode(
        base32::Alphabet::RFC4648 { padding: false },
        secret_base32,
    )
    .ok_or_else(|| AppError::BadRequest("invalid 2fa secret".to_string()))?;

    let now = Utc::now().timestamp();
    for offset in [-1, 0, 1] {
        let ts = now + offset * TOTP_STEP_SECONDS;
        if totp_code_for_timestamp(&secret, ts) == code {
            return Ok(true);
        }
    }

    Ok(false)
}

fn totp_code_for_timestamp(secret: &[u8], timestamp: i64) -> String {
    let counter = (timestamp / TOTP_STEP_SECONDS) as u64;
    let mut msg = [0_u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());

    let mut mac = HmacSha1::new_from_slice(secret).expect("hmac can be initialized");
    mac.update(&msg);
    let hash = mac.finalize().into_bytes();

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((hash[offset] & 0x7f) as u32) << 24
        | ((hash[offset + 1] & 0xff) as u32) << 16
        | ((hash[offset + 2] & 0xff) as u32) << 8
        | (hash[offset + 3] & 0xff) as u32;
    let modulo = 10_u32.pow(TOTP_DIGITS);
    let value = binary % modulo;
    format!("{:0width$}", value, width = TOTP_DIGITS as usize)
}
