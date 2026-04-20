use crate::{
    crypto::CryptoManager,
    domain::user::{CreateUserRequest, User},
    error::AppError,
    repository::{cache_repository, user_repository},
    state::AppState,
};

const USER_CACHE_TTL_SECONDS: u64 = 600;

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

        let normalized_email = payload.email.trim().to_lowercase();
        let encrypted_email = encrypt_user_email(
            &self.state.data_encryption_manager,
            payload.id,
            &normalized_email,
        )?;
        let email_blind_index =
            compute_email_blind_index(&self.state.blind_index_key, &normalized_email)?;
        let encrypted_date_of_birth = encrypt_date_of_birth(
            &self.state.data_encryption_manager,
            payload.id,
            &payload.date_of_birth,
        )?;
        let encrypted_bio = encrypt_optional_bio(
            &self.state.data_encryption_manager,
            payload.id,
            payload.bio.as_deref(),
        )?;

        let stored = user_repository::create_user(
            &self.state.pg_pool,
            user_repository::StoredCreateUser {
                id: payload.id,
                username: payload.username,
                display_name: payload.display_name,
                email: encrypted_email,
                email_blind_index,
                password_hash: payload.password_hash,
                date_of_birth: encrypted_date_of_birth,
                locale: payload.locale,
                avatar_url: payload.avatar_url,
                banner_url: payload.banner_url,
                accent_color: payload.accent_color,
                bio: encrypted_bio,
                pronouns: payload.pronouns,
            },
        )
        .await?;
        let user = build_user_response(&self.state.data_encryption_manager, stored)?;
        let cache_key = format!("cache:user:profile:{}", user.id);
        cache_repository::set_json(
            &self.state.redis_pool,
            &cache_key,
            &user,
            USER_CACHE_TTL_SECONDS,
        )
        .await?;
        Ok(user)
    }

    pub async fn get_user(&self, id: i64) -> Result<User, AppError> {
        let cache_key = format!("cache:user:profile:{id}");
        if let Some(cached) =
            cache_repository::get_json::<User>(&self.state.redis_pool, &cache_key).await?
        {
            return Ok(cached);
        }

        let user = user_repository::get_user(&self.state.pg_pool, id)
            .await?
            .ok_or(AppError::NotFound)
            .and_then(|row| build_user_response(&self.state.data_encryption_manager, row))?;

        cache_repository::set_json(
            &self.state.redis_pool,
            &cache_key,
            &user,
            USER_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(user)
    }

    pub async fn update_avatar_url(&self, user_id: i64, avatar_url: &str) -> Result<(), AppError> {
        user_repository::update_avatar_url(&self.state.pg_pool, user_id, avatar_url).await?;
        let cache_key = format!("cache:user:profile:{user_id}");
        cache_repository::del_key(&self.state.redis_pool, &cache_key).await?;
        Ok(())
    }
}

fn compute_email_blind_index(blind_index_key: &str, email: &str) -> Result<String, AppError> {
    crate::crypto::blind_index_string(blind_index_key, email)
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
    if value.starts_with("v1.") {
        let aad = user_field_aad(user_id, field);
        return crypto.decrypt_to_string(value, Some(&aad));
    }
    Ok(value.to_string())
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

fn decrypt_date_of_birth(
    crypto: &CryptoManager,
    user_id: i64,
    date_of_birth: &str,
) -> Result<chrono::NaiveDate, AppError> {
    let value = decrypt_user_field(crypto, user_id, "date_of_birth", date_of_birth)?;
    chrono::NaiveDate::parse_from_str(&value, "%Y-%m-%d")
        .map_err(|err| AppError::Crypto(format!("invalid date_of_birth payload: {err}")))
}

fn encrypt_optional_bio(
    crypto: &CryptoManager,
    user_id: i64,
    bio: Option<&str>,
) -> Result<Option<String>, AppError> {
    bio.map(|value| encrypt_user_field(crypto, user_id, "bio", value))
        .transpose()
}

fn decrypt_optional_bio(
    crypto: &CryptoManager,
    user_id: i64,
    bio: Option<&str>,
) -> Result<Option<String>, AppError> {
    bio.map(|value| decrypt_user_field(crypto, user_id, "bio", value))
        .transpose()
}

fn build_user_response(
    crypto: &CryptoManager,
    row: user_repository::StoredUserRow,
) -> Result<User, AppError> {
    Ok(User {
        id: row.id,
        username: row.username,
        display_name: row.display_name,
        email: decrypt_user_email(crypto, row.id, &row.email)?,
        email_verified: row.email_verified,
        token_version: row.token_version,
        account_status: row.account_status,
        flags: row.flags,
        last_login_at: row.last_login_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
        date_of_birth: decrypt_date_of_birth(crypto, row.id, &row.date_of_birth)?,
        avatar_url: row.avatar_url,
        banner_url: row.banner_url,
        accent_color: row.accent_color,
        bio: decrypt_optional_bio(crypto, row.id, row.bio.as_deref())?,
        pronouns: row.pronouns,
        locale: row.locale,
    })
}
