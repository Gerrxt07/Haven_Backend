use crate::{error::AppError, state::AppState};
use chrono::{Datelike, Local, TimeZone, Timelike};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub fn spawn_avatar_cleanup(state: AppState) {
    tokio::spawn(async move {
        loop {
            let sleep_for = time_until_next_run(1, 0);
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

fn time_until_next_run(hour: u32, minute: u32) -> Duration {
    let now = Local::now();
    let today = now.date_naive();
    let mut target = Local
        .from_local_datetime(&today.and_hms_opt(hour, minute, 0).unwrap())
        .single()
        .unwrap_or(now);

    if target <= now {
        let tomorrow = today.succ_opt().unwrap_or(today);
        target = Local
            .from_local_datetime(&tomorrow.and_hms_opt(hour, minute, 0).unwrap())
            .single()
            .unwrap_or(now + chrono::Duration::hours(24));
    }

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

fn parse_user_id_from_path(path: &Path) -> Option<i64> {
    let name = path.file_name()?.to_string_lossy();
    name.parse::<i64>().ok()
}
