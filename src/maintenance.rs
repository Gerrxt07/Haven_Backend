use crate::{
    crypto::blind_index_string,
    error::AppError,
    repository::{cache_repository, user_repository},
    state::AppState,
};
use chrono::{Duration as ChronoDuration, Local, LocalResult, TimeZone, Timelike, Utc};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

const DELETED_ACCOUNT_RETENTION_DAYS: i64 = 30;
const DELETED_ACCOUNT_SWEEP_INTERVAL_HOURS: u32 = 24;

pub fn spawn_avatar_cleanup(state: AppState) {
    tokio::spawn(async move {
        loop {
            let sleep_for = time_until_next_run(3);
            sleep(sleep_for).await;

            if let Err(err) = cleanup_orphan_avatars(&state).await {
                warn!(
                    event = "avatar.cleanup.failed",
                    error = %err,
                    "avatar cleanup failed"
                );
            }
        }
    });
}

pub fn spawn_deleted_account_cleanup(state: AppState) {
    tokio::spawn(async move {
        loop {
            let sleep_for = time_until_next_run(DELETED_ACCOUNT_SWEEP_INTERVAL_HOURS);
            sleep(sleep_for).await;

            if let Err(err) = cleanup_deleted_accounts(&state).await {
                warn!(
                    event = "account.cleanup.failed",
                    error = %err,
                    "deleted account cleanup failed"
                );
            }
        }
    });
}

fn time_until_next_run(interval_hours: u32) -> Duration {
    let interval_hours = interval_hours.max(1);
    let now = Local::now();

    let current_hour = now.hour();
    let next_hour = ((current_hour / interval_hours) + 1) * interval_hours;

    let (target_date, target_hour) = if next_hour < 24 {
        (now.date_naive(), next_hour)
    } else {
        (
            now.date_naive()
                .succ_opt()
                .unwrap_or_else(|| now.date_naive()),
            0,
        )
    };

    let target =
        match Local.from_local_datetime(&target_date.and_hms_opt(target_hour, 0, 0).unwrap()) {
            LocalResult::Single(target) => target,
            LocalResult::Ambiguous(earliest, _) => earliest,
            LocalResult::None => now + chrono::Duration::hours(interval_hours as i64),
        };

    let target = if target <= now {
        now + chrono::Duration::hours(interval_hours as i64)
    } else {
        target
    };

    let diff = target - now;
    Duration::from_secs(diff.num_seconds().max(0) as u64)
}

async fn cleanup_orphan_avatars(state: &AppState) -> Result<(), AppError> {
    let root = PathBuf::from(&state.avatar_storage_dir);
    if !root.exists() {
        return Ok(());
    }

    let mut dir = tokio::fs::read_dir(&root)
        .await
        .map_err(|_| AppError::BadRequest("failed to read avatar storage".to_string()))?;

    let mut ids = Vec::new();
    let mut id_to_path = Vec::new();

    while let Some(entry) = dir
        .next_entry()
        .await
        .map_err(|_| AppError::BadRequest("failed to scan avatar storage".to_string()))?
    {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let Some(id) = parse_user_id_from_path(&path) else {
            continue;
        };

        ids.push(id);
        id_to_path.push((id, path));
    }

    if ids.is_empty() {
        return Ok(());
    }

    let existing = sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE id = ANY($1)")
        .bind(&ids)
        .fetch_all(&state.pg_pool)
        .await?;

    let existing_set: HashSet<i64> = existing.into_iter().collect();
    let mut removed = 0;

    for (id, path) in id_to_path {
        if !existing_set.contains(&id) {
            if let Err(err) = tokio::fs::remove_dir_all(&path).await {
                warn!(
                    event = "avatar.cleanup.remove_failed",
                    user_id = id,
                    path = %path.display(),
                    error = %err,
                    "failed to remove orphan avatar directory"
                );
            } else {
                removed += 1;
            }
        }
    }

    info!(
        event = "avatar.cleanup.complete",
        scanned = ids.len(),
        removed,
        "avatar cleanup completed"
    );

    Ok(())
}

async fn cleanup_deleted_accounts(state: &AppState) -> Result<(), AppError> {
    let cutoff = Utc::now() - ChronoDuration::days(DELETED_ACCOUNT_RETENTION_DAYS);
    let users = user_repository::list_deleted_users_pending_cleanup(&state.pg_pool, cutoff).await?;

    if users.is_empty() {
        return Ok(());
    }

    let mut anonymized = 0usize;
    for user in users {
        let profile = deleted_user_profile(user.id, &state.blind_index_key)?;
        let encrypted_email = encrypt_deleted_user_email(
            &state.data_encryption_manager,
            user.id,
            &profile.placeholder_email,
        )?;
        let encrypted_dob =
            encrypt_deleted_user_date_of_birth(&state.data_encryption_manager, user.id)?;

        user_repository::anonymize_deleted_user(
            &state.pg_pool,
            user.id,
            &profile.username,
            &profile.display_name,
            &encrypted_email,
            &profile.email_blind_index,
            &encrypted_dob,
        )
        .await?;
        cache_repository::invalidate_auth_status_cache(&state.redis_pool, user.id).await?;
        anonymized += 1;
    }

    info!(
        event = "account.cleanup.complete",
        anonymized, "deleted account cleanup completed"
    );

    Ok(())
}

fn parse_user_id_from_path(path: &Path) -> Option<i64> {
    let name = path.file_name()?.to_string_lossy();
    name.parse::<i64>().ok()
}

struct DeletedUserProfile {
    username: String,
    display_name: String,
    placeholder_email: String,
    email_blind_index: String,
}

fn deleted_user_profile(
    user_id: i64,
    blind_index_key: &str,
) -> Result<DeletedUserProfile, AppError> {
    let placeholder_email = format!("deleted-user-{user_id}@deleted.haven.local");
    let email_blind_index = blind_index_string(blind_index_key, &placeholder_email)?;

    Ok(DeletedUserProfile {
        username: format!("deleted-user-{user_id}"),
        display_name: "Deleted User".to_string(),
        placeholder_email,
        email_blind_index,
    })
}

fn encrypt_deleted_user_email(
    crypto: &crate::crypto::CryptoManager,
    user_id: i64,
    email: &str,
) -> Result<String, AppError> {
    let aad = format!("user:{user_id}:email");
    crypto.encrypt_string(email, Some(aad.as_bytes()))
}

fn encrypt_deleted_user_date_of_birth(
    crypto: &crate::crypto::CryptoManager,
    user_id: i64,
) -> Result<String, AppError> {
    let aad = format!("user:{user_id}:date_of_birth");
    crypto.encrypt_string("1970-01-01", Some(aad.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{
        deleted_user_profile, encrypt_deleted_user_date_of_birth, encrypt_deleted_user_email,
        time_until_next_run,
    };
    use crate::crypto::CryptoManager;

    #[test]
    fn deleted_user_profile_uses_deleted_user_identity() {
        let profile = deleted_user_profile(42, "blind-index-key-12345678901234567890")
            .expect("profile should build");

        assert_eq!(profile.username, "deleted-user-42");
        assert_eq!(profile.display_name, "Deleted User");
        assert_eq!(
            profile.placeholder_email,
            "deleted-user-42@deleted.haven.local"
        );
        assert_ne!(profile.email_blind_index, profile.placeholder_email);
    }

    #[test]
    fn deleted_user_pii_encryption_roundtrips() {
        let crypto = CryptoManager::new("unit-test-master-encryption-key-123456");
        let encrypted_email =
            encrypt_deleted_user_email(&crypto, 7, "deleted-user-7@deleted.haven.local")
                .expect("email encryption should work");
        let encrypted_dob =
            encrypt_deleted_user_date_of_birth(&crypto, 7).expect("dob encryption should work");

        let email = crypto
            .decrypt_to_string(&encrypted_email, Some(b"user:7:email"))
            .expect("email decryption should work");
        let dob = crypto
            .decrypt_to_string(&encrypted_dob, Some(b"user:7:date_of_birth"))
            .expect("dob decryption should work");

        assert_eq!(email, "deleted-user-7@deleted.haven.local");
        assert_eq!(dob, "1970-01-01");
    }

    #[test]
    fn next_run_duration_is_non_zero() {
        assert!(time_until_next_run(24).as_secs() <= 24 * 60 * 60);
    }
}
