use crate::{
    auth::{generate_id, hash_password, sha256_hex, verify_password, AuthTokens},
    crypto::{blind_index_string, CryptoManager},
    domain::auth::{
        AuthUser, AuthUserResponse, EmailVerificationConfirmRequest, EmailVerificationRequest,
        LoginChallengeRequest, LoginChallengeResponse, LoginRequest, LoginVerifyRequest,
        LoginVerifyResponse, RefreshRequest, RegisterRequest, StatusResponse,
        TwoFactorConfirmRequest, TwoFactorDisableRequest, TwoFactorSetupResponse,
    },
    error::AppError,
    repository::{auth_repository, cache_repository},
    state::AppState,
};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
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
const AUTH_STATUS_CACHE_TTL_SECONDS: u64 = 120;
const LEGACY_PASSWORD_MIN_LEN: usize = 10;
const LEGACY_PASSWORD_MAX_LEN: usize = 128;

#[derive(Serialize, Deserialize)]
struct CachedAuthStatus {
    account_status: String,
    token_version: i32,
}

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

        if let Some(password) = payload.password.as_deref() {
            if !(LEGACY_PASSWORD_MIN_LEN..=LEGACY_PASSWORD_MAX_LEN).contains(&password.len()) {
                return Err(AppError::Validation(
                    "password must be between 10 and 128 characters".to_string(),
                ));
            }
        }

        let user_id = generate_id();
        let normalized_email = payload.email.trim().to_lowercase();
        let encrypted_email = encrypt_user_email(
            &self.state.data_encryption_manager,
            user_id,
            &normalized_email,
        )?;
        let email_blind_index =
            compute_email_blind_index(&self.state.blind_index_key, &normalized_email)?;
        let encrypted_date_of_birth = encrypt_date_of_birth(
            &self.state.data_encryption_manager,
            user_id,
            &payload.date_of_birth,
        )?;

        let password_hash = payload.password.as_deref().map(hash_password).transpose()?;

        let stored_user = auth_repository::insert_user_for_registration(
            &self.state.pg_pool,
            auth_repository::NewRegistrationUser {
                user_id,
                username: payload.username.trim().to_lowercase(),
                display_name: payload.display_name.trim().to_string(),
                email: encrypted_email,
                email_blind_index,
                srp_salt: payload.srp_salt,
                srp_verifier: payload.srp_verifier,
                password_hash,
                date_of_birth: encrypted_date_of_birth,
                locale: payload.locale.trim().to_lowercase(),
            },
        )
        .await?;
        let user = build_auth_user_response(&self.state.data_encryption_manager, stored_user)?;

        tracing::info!(
            event = "auth.register",
            user_id = user.id,
            email = normalized_email,
            "user registered"
        );
        Ok(user)
    }

    /// Step 1 of SRP login: Generate challenge
    pub async fn login_challenge(
        &self,
        payload: LoginChallengeRequest,
    ) -> Result<(String, LoginChallengeResponse), AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let normalized_email = payload.email.trim().to_lowercase();

        let email_blind_index =
            compute_email_blind_index(&self.state.blind_index_key, &normalized_email)?;
        let user = match auth_repository::find_user_auth_by_email_blind_index(
            &self.state.pg_pool,
            &email_blind_index,
        )
        .await?
        {
            Some(user) => user,
            None => {
                tracing::warn!(
                    event = "auth.login.challenge.failed",
                    email = normalized_email,
                    reason = "user_not_found",
                    "invalid credentials"
                );
                return Err(AppError::Unauthorized);
            }
        };

        if user.account_status != "active" {
            tracing::warn!(
                event = "auth.login.challenge.blocked",
                user_id = user.id,
                status = user.account_status,
                "blocked login due to account status"
            );
            return Err(AppError::Forbidden);
        }

        // Get SRP salt and verifier
        let (salt, verifier) = match (user.srp_salt, user.srp_verifier) {
            (Some(salt), Some(verifier)) => (salt, verifier),
            _ => {
                tracing::warn!(
                    event = "auth.login.challenge.failed",
                    user_id = user.id,
                    reason = "srp_not_configured",
                    "SRP login attempted for account without SRP credentials"
                );
                return Err(AppError::Unauthorized);
            }
        };

        // Decode from base64
        let _salt_bytes = STANDARD
            .decode(&salt)
            .map_err(|_| AppError::BadRequest("invalid salt".to_string()))?;
        let verifier_bytes = STANDARD
            .decode(&verifier)
            .map_err(|_| AppError::BadRequest("invalid verifier".to_string()))?;

        // Generate SRP challenge
        let (challenge_id, server_public_key_b) = self
            .state
            .srp_service
            .generate_challenge(&normalized_email, verifier_bytes)
            .map_err(|error| {
                tracing::error!(
                    event = "auth.login.challenge.failed",
                    user_id = user.id,
                    reason = "srp_generation_failed",
                    ?error,
                    "failed to generate SRP challenge"
                );
                AppError::Unauthorized
            })?;

        tracing::info!(
            event = "auth.login.challenge",
            user_id = user.id,
            "SRP login challenge generated"
        );

        Ok((
            challenge_id.clone(),
            LoginChallengeResponse {
                challenge_id,
                srp_salt: salt,
                server_public_key_b,
            },
        ))
    }

    /// Step 2 of SRP login: Verify client proof and issue tokens
    pub async fn login_verify(
        &self,
        challenge_id: String,
        payload: LoginVerifyRequest,
    ) -> Result<LoginVerifyResponse, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let normalized_email = payload.email.trim().to_lowercase();

        let email_blind_index =
            compute_email_blind_index(&self.state.blind_index_key, &normalized_email)?;
        let user = match auth_repository::find_user_auth_by_email_blind_index(
            &self.state.pg_pool,
            &email_blind_index,
        )
        .await?
        {
            Some(user) => user,
            None => {
                tracing::warn!(
                    event = "auth.login.verify.failed",
                    email = normalized_email,
                    reason = "user_not_found",
                    "invalid credentials"
                );
                return Err(AppError::Unauthorized);
            }
        };

        if user.account_status != "active" {
            return Err(AppError::Forbidden);
        }

        let salt = user
            .srp_salt
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized)
            .and_then(|salt| {
                STANDARD
                    .decode(salt)
                    .map_err(|_| AppError::BadRequest("invalid salt".to_string()))
            })?;

        // Decode client public key and proof from base64
        let client_public_key_a = STANDARD
            .decode(&payload.client_public_key_a)
            .map_err(|_| AppError::BadRequest("invalid client public key".to_string()))?;
        let client_proof_m1 = STANDARD
            .decode(&payload.client_proof_m1)
            .map_err(|_| AppError::BadRequest("invalid client proof".to_string()))?;

        // Verify client proof and get server proof
        let server_proof_m2 = self
            .state
            .srp_service
            .verify_challenge(
                &challenge_id,
                &normalized_email,
                &salt,
                client_public_key_a,
                client_proof_m1,
            )
            .map_err(|e| {
                tracing::warn!(
                    event = "auth.login.verify.failed",
                    user_id = user.id,
                    reason = "invalid_proof",
                    "SRP verification failed: {:?}",
                    e
                );
                AppError::Unauthorized
            })?;

        // Handle 2FA if enabled
        if let Some(secret) = user
            .totp_secret
            .as_deref()
            .map(|value| decrypt_totp_secret(&self.state.data_encryption_manager, user.id, value))
            .transpose()?
        {
            match (payload.totp_code.as_deref(), payload.backup_code.as_deref()) {
                (Some(code), _) => {
                    if !verify_totp_code(&secret, code)? {
                        tracing::warn!(
                            event = "auth.login.verify.failed",
                            email = payload.email,
                            reason = "invalid_totp",
                            "invalid 2fa code"
                        );
                        return Err(AppError::Unauthorized);
                    }
                }
                (None, Some(backup_code)) => {
                    let current_codes = decrypt_backup_code_hashes(
                        &self.state.data_encryption_manager,
                        user.id,
                        user.totp_backup_codes.as_deref(),
                    )?;
                    let updated_codes = consume_backup_code(&current_codes, backup_code)
                        .ok_or_else(|| {
                            tracing::warn!(
                                event = "auth.login.verify.failed",
                                email = payload.email,
                                reason = "invalid_backup_code",
                                "invalid backup code"
                            );
                            AppError::Unauthorized
                        })?;
                    let encrypted_codes = encrypt_backup_code_hashes(
                        &self.state.data_encryption_manager,
                        user.id,
                        &updated_codes,
                    )?;
                    auth_repository::update_backup_codes(
                        &self.state.pg_pool,
                        user.id,
                        encrypted_codes,
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
            event = "auth.login.verify",
            user_id = user.id,
            session_id,
            "SRP login successful"
        );

        Ok(LoginVerifyResponse {
            server_proof_m2: STANDARD.encode(server_proof_m2),
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: "Bearer",
            expires_in_seconds: tokens.expires_in_seconds,
        })
    }

    pub async fn login(&self, payload: LoginRequest) -> Result<AuthTokens, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let normalized_email = payload.email.trim().to_lowercase();

        let email_blind_index =
            compute_email_blind_index(&self.state.blind_index_key, &normalized_email)?;
        let user = match auth_repository::find_user_auth_by_email_blind_index(
            &self.state.pg_pool,
            &email_blind_index,
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

        // Legacy password verification (for backward compatibility during transition)
        let password_hash = user.password_hash.ok_or_else(|| {
            tracing::warn!(
                event = "auth.login.failed",
                user_id = user.id,
                reason = "password_login_not_available",
                "legacy password login attempted for SRP-only account"
            );
            AppError::Unauthorized
        })?;

        if !verify_password(&password_hash, &payload.password) {
            tracing::warn!(
                event = "auth.login.failed",
                email = payload.email,
                "invalid password"
            );
            return Err(AppError::Unauthorized);
        }

        if let Some(secret) = user
            .totp_secret
            .as_deref()
            .map(|value| decrypt_totp_secret(&self.state.data_encryption_manager, user.id, value))
            .transpose()?
        {
            match (payload.totp_code.as_deref(), payload.backup_code.as_deref()) {
                (Some(code), _) => {
                    if !verify_totp_code(&secret, code)? {
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
                    let current_codes = decrypt_backup_code_hashes(
                        &self.state.data_encryption_manager,
                        user.id,
                        user.totp_backup_codes.as_deref(),
                    )?;
                    let updated_codes = consume_backup_code(&current_codes, backup_code)
                        .ok_or_else(|| {
                            tracing::warn!(
                                event = "auth.login.failed",
                                email = payload.email,
                                reason = "invalid_backup_code",
                                "invalid backup code"
                            );
                            AppError::Unauthorized
                        })?;
                    let encrypted_codes = encrypt_backup_code_hashes(
                        &self.state.data_encryption_manager,
                        user.id,
                        &updated_codes,
                    )?;
                    auth_repository::update_backup_codes(
                        &self.state.pg_pool,
                        user.id,
                        encrypted_codes,
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
            .and_then(|row| build_auth_user_response(&self.state.data_encryption_manager, row))
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
        let email_blind_index =
            compute_email_blind_index(&self.state.blind_index_key, &normalized_email)?;

        let ip = crate::security::extract_client_ip(headers);
        let ip_key = format!("email-verify:ip:{ip}");
        if !self.state.email_verify_ip_limiter.allow(&ip_key).await {
            return Err(AppError::TooManyRequests);
        }

        let email_key = format!("email-verify:email:{normalized_email}");
        if !self
            .state
            .email_verify_email_limiter
            .allow(&email_key)
            .await
        {
            return Err(AppError::TooManyRequests);
        }

        let user = match auth_repository::find_user_email_status_by_blind_index(
            &self.state.pg_pool,
            &email_blind_index,
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

        if let Err(error) = self
            .state
            .email_client
            .send_verification_code(&normalized_email, &code, EMAIL_VERIFICATION_TTL_MINUTES)
            .await
        {
            tracing::error!(
                event = "auth.email_verification.request.send_failed",
                user_id = user.id,
                email = normalized_email,
                ?error,
                "verification email send failed after code persisted"
            );
        }

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
        let email_blind_index =
            compute_email_blind_index(&self.state.blind_index_key, &normalized_email)?;
        let user = auth_repository::find_user_email_status_by_blind_index(
            &self.state.pg_pool,
            &email_blind_index,
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
            return Err(AppError::BadRequest(
                "verification code expired".to_string(),
            ));
        }

        let incoming_hash = sha256_hex(payload.code.trim());
        if incoming_hash != latest_code.code_hash {
            return Err(AppError::BadRequest(
                "invalid verification code".to_string(),
            ));
        }

        auth_repository::mark_email_verification_code_consumed(&self.state.pg_pool, latest_code.id)
            .await?;
        auth_repository::set_email_verified(&self.state.pg_pool, user.id).await?;

        Ok(StatusResponse { status: "verified" })
    }

    pub async fn setup_two_factor(
        &self,
        headers: &HeaderMap,
    ) -> Result<TwoFactorSetupResponse, AppError> {
        let user = self.authenticate_from_headers(headers).await?;
        let current = auth_repository::find_user_auth_by_id(&self.state.pg_pool, user.id).await?;

        if current.totp_secret.is_some() {
            return Err(AppError::Conflict("2fa already enabled".to_string()));
        }

        let secret = generate_totp_secret();
        let backup_codes = generate_backup_codes();
        let hashed_backup_codes = hash_backup_codes(&backup_codes);
        let encrypted_secret =
            encrypt_totp_secret(&self.state.data_encryption_manager, user.id, &secret)?;
        let encrypted_backup_codes = encrypt_backup_code_hashes(
            &self.state.data_encryption_manager,
            user.id,
            &hashed_backup_codes,
        )?;
        let expires_at = Utc::now() + Duration::minutes(TOTP_SETUP_TTL_MINUTES);

        auth_repository::upsert_totp_setup(
            &self.state.pg_pool,
            user.id,
            encrypted_secret,
            encrypted_backup_codes,
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

        let secret =
            decrypt_totp_secret(&self.state.data_encryption_manager, user.id, &setup.secret)?;
        if !verify_totp_code(&secret, payload.code.trim())? {
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
        let current = auth_repository::find_user_auth_by_id(&self.state.pg_pool, user.id).await?;

        let secret = current
            .totp_secret
            .as_deref()
            .map(|value| decrypt_totp_secret(&self.state.data_encryption_manager, user.id, value))
            .transpose()?
            .ok_or_else(|| AppError::BadRequest("2fa not enabled".to_string()))?;

        let mut backup_codes = decrypt_backup_code_hashes(
            &self.state.data_encryption_manager,
            user.id,
            current.totp_backup_codes.as_deref(),
        )?;

        let mut verified = false;
        if let Some(code) = payload.code.as_deref() {
            verified = verify_totp_code(&secret, code.trim())?;
        }

        if !verified {
            if let Some(backup_code) = payload.backup_code.as_deref() {
                if let Some(updated) = consume_backup_code(&backup_codes, backup_code) {
                    backup_codes = updated;
                    let encrypted_codes = encrypt_backup_code_hashes(
                        &self.state.data_encryption_manager,
                        user.id,
                        &backup_codes,
                    )?;
                    auth_repository::update_backup_codes(
                        &self.state.pg_pool,
                        user.id,
                        encrypted_codes,
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

    pub async fn authenticate_access_token(&self, bearer: &str) -> Result<AuthUser, AppError> {
        let claims = self
            .state
            .token_manager
            .parse_and_validate(bearer, "access")?;
        self.authenticate_access_claims(claims.user_id, claims.token_version)
            .await
    }

    async fn authenticate_from_headers(&self, headers: &HeaderMap) -> Result<AuthUser, AppError> {
        let bearer = extract_bearer(headers)?;
        self.authenticate_access_token(&bearer).await
    }

    async fn authenticate_access_claims(
        &self,
        user_id: i64,
        token_version: i32,
    ) -> Result<AuthUser, AppError> {
        let status_cache_key = format!("cache:auth:status:{user_id}");
        let status_row = if let Some(cached) = cache_repository::get_json::<CachedAuthStatus>(
            &self.state.redis_pool,
            &status_cache_key,
        )
        .await?
        {
            (cached.account_status, cached.token_version)
        } else {
            let row = auth_repository::find_status_and_token_version(&self.state.pg_pool, user_id)
                .await?
                .ok_or(AppError::Unauthorized)?;

            let cached = CachedAuthStatus {
                account_status: row.0.clone(),
                token_version: row.1,
            };

            cache_repository::set_json(
                &self.state.redis_pool,
                &status_cache_key,
                &cached,
                AUTH_STATUS_CACHE_TTL_SECONDS,
            )
            .await?;

            row
        };

        if status_row.0 != "active" {
            return Err(AppError::Forbidden);
        }

        if status_row.1 != token_version {
            return Err(AppError::Unauthorized);
        }

        Ok(AuthUser { id: user_id })
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
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret)
}

fn build_otpauth_url(secret: &str, user_id: i64) -> String {
    let s = format!("Haven:{user_id}");
    let label = encode(&s);
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

fn totp_secret_aad(user_id: i64) -> Vec<u8> {
    format!("totp:secret:{user_id}").into_bytes()
}

fn totp_backup_codes_aad(user_id: i64) -> Vec<u8> {
    format!("totp:backup-codes:{user_id}").into_bytes()
}

fn encrypt_totp_secret(
    crypto: &CryptoManager,
    user_id: i64,
    secret: &str,
) -> Result<String, AppError> {
    let aad = totp_secret_aad(user_id);
    crypto.encrypt_string(secret, Some(&aad))
}

fn decrypt_totp_secret(
    crypto: &CryptoManager,
    user_id: i64,
    value: &str,
) -> Result<String, AppError> {
    let aad = totp_secret_aad(user_id);
    crypto.decrypt_to_string(value, Some(&aad))
}

fn encrypt_backup_code_hashes(
    crypto: &CryptoManager,
    user_id: i64,
    hashes: &[String],
) -> Result<String, AppError> {
    let aad = totp_backup_codes_aad(user_id);
    let payload = serde_json::to_string(hashes)
        .map_err(|err| AppError::Service(format!("failed to serialize backup codes: {err}")))?;
    crypto.encrypt_string(&payload, Some(&aad))
}

fn decrypt_backup_code_hashes(
    crypto: &CryptoManager,
    user_id: i64,
    value: Option<&str>,
) -> Result<Vec<String>, AppError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let aad = totp_backup_codes_aad(user_id);
    let plaintext = crypto.decrypt_to_string(value, Some(&aad))?;
    serde_json::from_str(&plaintext)
        .map_err(|err| AppError::Crypto(format!("invalid backup code payload: {err}")))
}

fn compute_email_blind_index(blind_index_key: &str, email: &str) -> Result<String, AppError> {
    blind_index_string(blind_index_key, email)
}

fn user_field_aad(user_id: i64, field: &str) -> Vec<u8> {
    format!("user:{user_id}:{field}").into_bytes()
}

fn encrypt_user_field(
    crypto: &CryptoManager,
    user_id: i64,
    field: &str,
    value: &str,
) -> Result<String, AppError> {
    let aad = user_field_aad(user_id, field);
    crypto.encrypt_string(value, Some(&aad))
}

fn decrypt_user_field(
    crypto: &CryptoManager,
    user_id: i64,
    field: &str,
    value: &str,
) -> Result<String, AppError> {
    let aad = user_field_aad(user_id, field);
    crypto.decrypt_to_string(value, Some(&aad))
}

fn encrypt_user_email(
    crypto: &CryptoManager,
    user_id: i64,
    email: &str,
) -> Result<String, AppError> {
    encrypt_user_field(crypto, user_id, "email", email)
}

fn decrypt_user_email(
    crypto: &CryptoManager,
    user_id: i64,
    email: &str,
) -> Result<String, AppError> {
    decrypt_user_field(crypto, user_id, "email", email)
}

fn encrypt_date_of_birth(
    crypto: &CryptoManager,
    user_id: i64,
    date_of_birth: &chrono::NaiveDate,
) -> Result<String, AppError> {
    encrypt_user_field(crypto, user_id, "date_of_birth", &date_of_birth.to_string())
}

fn build_auth_user_response(
    crypto: &CryptoManager,
    row: auth_repository::StoredAuthUserResponseRow,
) -> Result<AuthUserResponse, AppError> {
    Ok(AuthUserResponse {
        id: row.id,
        username: row.username,
        display_name: row.display_name,
        email: decrypt_user_email(crypto, row.id, &row.email)?,
        avatar_url: row.avatar_url,
        email_verified: row.email_verified,
        two_factor_enabled: row.two_factor_enabled,
        account_status: row.account_status,
        token_version: row.token_version,
        created_at: row.created_at,
    })
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
    let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_base32)
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
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | hash[offset + 3] as u32;
    let modulo = 10_u32.pow(TOTP_DIGITS);
    let value = binary % modulo;
    format!("{:0width$}", value, width = TOTP_DIGITS as usize)
}

#[cfg(test)]
mod tests {
    use super::{
        compute_email_blind_index, decrypt_backup_code_hashes, decrypt_totp_secret,
        decrypt_user_email, encrypt_backup_code_hashes, encrypt_date_of_birth, encrypt_totp_secret,
        encrypt_user_email,
    };
    use crate::crypto::CryptoManager;
    use chrono::NaiveDate;

    #[test]
    fn email_blind_index_is_stable() {
        let left =
            compute_email_blind_index("blind-index-key-12345678901234567890", "user@example.com")
                .expect("blind index should work");
        let right =
            compute_email_blind_index("blind-index-key-12345678901234567890", "user@example.com")
                .expect("blind index should work");

        assert_eq!(left, right);
    }

    #[test]
    fn totp_secret_roundtrips_with_master_key() {
        let crypto = CryptoManager::new("unit-test-master-encryption-key-123456");
        let encrypted =
            encrypt_totp_secret(&crypto, 42, "ABCDEFGH").expect("secret encryption should work");

        assert_ne!(encrypted, "ABCDEFGH");
        let decrypted =
            decrypt_totp_secret(&crypto, 42, &encrypted).expect("secret decryption should work");
        assert_eq!(decrypted, "ABCDEFGH");
    }

    #[test]
    fn backup_code_hashes_roundtrip_with_master_key() {
        let crypto = CryptoManager::new("unit-test-master-encryption-key-123456");
        let hashes = vec!["hash-1".to_string(), "hash-2".to_string()];

        let encrypted = encrypt_backup_code_hashes(&crypto, 42, &hashes)
            .expect("backup code encryption should work");
        let decrypted = decrypt_backup_code_hashes(&crypto, 42, Some(&encrypted))
            .expect("backup code decryption should work");

        assert_eq!(decrypted, hashes);
    }

    #[test]
    fn encrypted_email_roundtrips() {
        let crypto = CryptoManager::new("unit-test-master-encryption-key-123456");
        let encrypted =
            encrypt_user_email(&crypto, 42, "user@example.com").expect("email encrypts");
        let decrypted = decrypt_user_email(&crypto, 42, &encrypted).expect("email decrypts");

        assert_eq!(decrypted, "user@example.com");
        assert_ne!(encrypted, "user@example.com");
    }

    #[test]
    fn encrypted_date_of_birth_roundtrips() {
        let crypto = CryptoManager::new("unit-test-master-encryption-key-123456");
        let date = NaiveDate::from_ymd_opt(2000, 1, 1).expect("valid date");
        let encrypted = encrypt_date_of_birth(&crypto, 9, &date).expect("dob encrypts");
        let decrypted = super::decrypt_user_field(&crypto, 9, "date_of_birth", &encrypted)
            .expect("dob decrypts");

        assert_eq!(decrypted, date.to_string());
    }
}
