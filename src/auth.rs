use crate::error::AppError;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use rusty_paseto::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

#[derive(Clone)]
pub struct TokenManager {
    key_bytes: [u8; 32],
    access_token_ttl_minutes: i64,
    refresh_token_ttl_days: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub user_id: i64,
    pub session_id: i64,
    pub token_version: i32,
    pub token_type: String,
    pub exp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in_seconds: i64,
}

impl TokenManager {
    pub fn new(secret: &str, access_token_ttl_minutes: i64, refresh_token_ttl_days: i64) -> Self {
        let digest = Sha256::digest(secret.as_bytes());
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(&digest[..32]);

        Self {
            key_bytes,
            access_token_ttl_minutes,
            refresh_token_ttl_days,
        }
    }

    fn key(&self) -> PasetoSymmetricKey<V4, Local> {
        PasetoSymmetricKey::<V4, Local>::from(Key::from(self.key_bytes))
    }

    pub fn issue_tokens(
        &self,
        user_id: i64,
        session_id: i64,
        token_version: i32,
    ) -> Result<AuthTokens, AppError> {
        let access_exp = Utc::now() + Duration::minutes(self.access_token_ttl_minutes);
        let refresh_exp = Utc::now() + Duration::days(self.refresh_token_ttl_days);

        let access_token =
            self.build_token(user_id, session_id, token_version, "access", access_exp)?;
        let refresh_token =
            self.build_token(user_id, session_id, token_version, "refresh", refresh_exp)?;

        Ok(AuthTokens {
            access_token,
            refresh_token,
            token_type: "Bearer",
            expires_in_seconds: self.access_token_ttl_minutes * 60,
        })
    }

    pub fn refresh_ttl_days(&self) -> i64 {
        self.refresh_token_ttl_days
    }

    fn build_token(
        &self,
        user_id: i64,
        session_id: i64,
        token_version: i32,
        token_type: &str,
        exp: DateTime<Utc>,
    ) -> Result<String, AppError> {
        let exp_string = exp.to_rfc3339();
        let key = self.key();

        PasetoBuilder::<V4, Local>::default()
            .set_claim(ExpirationClaim::try_from(exp_string).map_err(|_| AppError::Unauthorized)?)
            .set_claim(CustomClaim::try_from(("uid", user_id)).map_err(|_| AppError::Unauthorized)?)
            .set_claim(
                CustomClaim::try_from(("sid", session_id)).map_err(|_| AppError::Unauthorized)?,
            )
            .set_claim(
                CustomClaim::try_from(("tv", token_version)).map_err(|_| AppError::Unauthorized)?,
            )
            .set_claim(
                CustomClaim::try_from(("typ", token_type)).map_err(|_| AppError::Unauthorized)?,
            )
            .build(&key)
            .map_err(|_| AppError::Unauthorized)
    }

    pub fn parse_and_validate(
        &self,
        token: &str,
        expected_type: &str,
    ) -> Result<TokenClaims, AppError> {
        let key = self.key();
        let value = PasetoParser::<V4, Local>::default()
            .parse(token, &key)
            .map_err(|_| AppError::Unauthorized)?;

        let uid = value
            .get("uid")
            .and_then(|v| v.as_i64())
            .ok_or(AppError::Unauthorized)?;
        let sid = value
            .get("sid")
            .and_then(|v| v.as_i64())
            .ok_or(AppError::Unauthorized)?;
        let tv = value
            .get("tv")
            .and_then(|v| v.as_i64())
            .ok_or(AppError::Unauthorized)?;
        let typ = value
            .get("typ")
            .and_then(|v| v.as_str())
            .ok_or(AppError::Unauthorized)?;
        let exp_raw = value
            .get("exp")
            .and_then(|v| v.as_str())
            .ok_or(AppError::Unauthorized)?;

        if typ != expected_type {
            return Err(AppError::Unauthorized);
        }

        let exp = DateTime::parse_from_rfc3339(exp_raw)
            .map_err(|_| AppError::Unauthorized)?
            .with_timezone(&Utc);

        if exp < Utc::now() {
            return Err(AppError::Unauthorized);
        }

        Ok(TokenClaims {
            user_id: uid,
            session_id: sid,
            token_version: tv as i32,
            token_type: typ.to_string(),
            exp,
        })
    }
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|p| p.to_string())
        .map_err(|_| AppError::BadRequest("failed to hash password".to_string()))
}

pub fn verify_password(password_hash: &str, password: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(hash) => hash,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!("{digest:x}")
}

pub fn generate_id() -> i64 {
    let millis = Utc::now().timestamp_millis();
    let random_bits: i64 = (rand::random::<u16>() as i64) & 0x0fff;
    (millis << 12) | random_bits
}
