use crate::{error::AppError, state::AppState};
use chrono::{Local, LocalResult, TimeZone, Timelike};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

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

fn time_until_next_run(interval_hours: u32) -> Duration {
    let interval_hours = interval_hours.max(1);
    let now = Local::now();

    let current_hour = now.hour();
    let next_hour = ((current_hour / interval_hours) + 1) * interval_hours;

    let (target_date, target_hour) = if next_hour < 24 {
        (now.date_naive(), next_hour)
    } else {
        (
            now.date_naive().succ_opt().unwrap_or_else(|| now.date_naive()),
            0,
        )
    };

    let target = match Local.from_local_datetime(&target_date.and_hms_opt(target_hour, 0, 0).unwrap()) {
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

fn parse_user_id_from_path(path: &Path) -> Option<i64> {
    let name = path.file_name()?.to_string_lossy();
    name.parse::<i64>().ok()
}
