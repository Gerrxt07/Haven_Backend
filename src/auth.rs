use crate::error::AppError;
use chrono::{DateTime, Duration, Utc};
use rusty_paseto::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sonyflake::{Builder as SonyflakeBuilder, Sonyflake};
use std::{convert::TryFrom, error::Error, sync::OnceLock};

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

type MachineIdError = Box<dyn Error + Send + Sync + 'static>;
static ID_GENERATOR: OnceLock<Sonyflake> = OnceLock::new();

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

pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!("{digest:x}")
}

pub fn generate_id() -> i64 {
    let raw_id = id_generator()
        .next_id()
        .expect("sonyflake id generation must succeed");
    i64::try_from(raw_id).expect("sonyflake ids must fit in signed 64-bit storage")
}

fn id_generator() -> &'static Sonyflake {
    ID_GENERATOR.get_or_init(|| {
        SonyflakeBuilder::new()
            .machine_id(&resolve_machine_id)
            .finalize()
            .expect("sonyflake generator must initialize")
    })
}

fn resolve_machine_id() -> Result<u16, MachineIdError> {
    if let Ok(raw) = std::env::var("HAVEN_MACHINE_ID") {
        return raw
            .parse::<u16>()
            .map_err(|err| format!("invalid HAVEN_MACHINE_ID '{raw}': {err}").into());
    }

    let machine_hint = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "haven-backend".to_string());
    let digest = Sha256::digest(machine_hint.as_bytes());
    Ok(u16::from_be_bytes([digest[0], digest[1]]))
}

#[cfg(test)]
mod tests {
    use super::generate_id;
    use std::collections::HashSet;

    #[test]
    fn generate_id_returns_positive_unique_values() {
        let mut values = HashSet::new();

        for _ in 0..1024 {
            let id = generate_id();
            assert!(id > 0);
            assert!(values.insert(id), "generated duplicate id: {id}");
        }
    }
}
