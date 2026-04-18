use crate::{
    domain::friends::{Friend, FriendRequest},
    error::AppError,
};
use sqlx::PgPool;

pub struct NewFriendRequest {
    pub id: i64,
    pub from_user_id: i64,
    pub to_user_id: i64,
}

pub async fn find_user_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<(i64, String, String)>, AppError> {
    let user = sqlx::query_as::<_, (i64, String, String)>(
        r#"
        SELECT id, username, display_name
        FROM users
        WHERE username = $1
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn are_friends(pool: &PgPool, user_a: i64, user_b: i64) -> Result<bool, AppError> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM friends WHERE user_id = $1 AND friend_user_id = $2",
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_optional(pool)
    .await?
    .is_some();

    Ok(exists)
}

pub async fn create_friend_request(
    pool: &PgPool,
    input: NewFriendRequest,
) -> Result<FriendRequest, AppError> {
    let request = sqlx::query_as::<_, FriendRequest>(
        r#"
        WITH inserted AS (
            INSERT INTO friend_requests (id, from_user_id, to_user_id, status)
            VALUES ($1, $2, $3, 'pending')
            RETURNING id, from_user_id, to_user_id, status, created_at, updated_at
        )
        SELECT
            i.id,
            i.from_user_id,
            fu.username AS from_username,
            fu.display_name AS from_display_name,
            fu.avatar_url AS from_avatar_url,
            i.to_user_id,
            tu.username AS to_username,
            tu.display_name AS to_display_name,
            i.status,
            i.created_at,
            i.updated_at
        FROM inserted i
        JOIN users fu ON fu.id = i.from_user_id
        JOIN users tu ON tu.id = i.to_user_id
        "#,
    )
    .bind(input.id)
    .bind(input.from_user_id)
    .bind(input.to_user_id)
    .fetch_one(pool)
    .await;

    match request {
        Ok(r) => Ok(r),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => Err(
            AppError::Conflict("a pending friend request already exists".to_string()),
        ),
        Err(err) => Err(AppError::Database(err)),
    }
}

pub async fn list_incoming_pending(
    pool: &PgPool,
    actor_user_id: i64,
) -> Result<Vec<FriendRequest>, AppError> {
    let requests = sqlx::query_as::<_, FriendRequest>(
        r#"
        SELECT
            fr.id,
            fr.from_user_id,
            fu.username AS from_username,
            fu.display_name AS from_display_name,
            fu.avatar_url AS from_avatar_url,
            fr.to_user_id,
            tu.username AS to_username,
            tu.display_name AS to_display_name,
            fr.status,
            fr.created_at,
            fr.updated_at
        FROM friend_requests fr
        JOIN users fu ON fu.id = fr.from_user_id
        JOIN users tu ON tu.id = fr.to_user_id
        WHERE fr.to_user_id = $1
          AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
        "#,
    )
    .bind(actor_user_id)
    .fetch_all(pool)
    .await?;

    Ok(requests)
}

pub async fn list_outgoing_pending(
    pool: &PgPool,
    actor_user_id: i64,
) -> Result<Vec<FriendRequest>, AppError> {
    let requests = sqlx::query_as::<_, FriendRequest>(
        r#"
        SELECT
            fr.id,
            fr.from_user_id,
            fu.username AS from_username,
            fu.display_name AS from_display_name,
            fu.avatar_url AS from_avatar_url,
            fr.to_user_id,
            tu.username AS to_username,
            tu.display_name AS to_display_name,
            fr.status,
            fr.created_at,
            fr.updated_at
        FROM friend_requests fr
        JOIN users fu ON fu.id = fr.from_user_id
        JOIN users tu ON tu.id = fr.to_user_id
        WHERE fr.from_user_id = $1
          AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
        "#,
    )
    .bind(actor_user_id)
    .fetch_all(pool)
    .await?;

    Ok(requests)
}

pub async fn get_friend_request_by_id(
    pool: &PgPool,
    request_id: i64,
) -> Result<Option<FriendRequest>, AppError> {
    let request = sqlx::query_as::<_, FriendRequest>(
        r#"
        SELECT
            fr.id,
            fr.from_user_id,
            fu.username AS from_username,
            fu.display_name AS from_display_name,
            fu.avatar_url AS from_avatar_url,
            fr.to_user_id,
            tu.username AS to_username,
            tu.display_name AS to_display_name,
            fr.status,
            fr.created_at,
            fr.updated_at
        FROM friend_requests fr
        JOIN users fu ON fu.id = fr.from_user_id
        JOIN users tu ON tu.id = fr.to_user_id
        WHERE fr.id = $1
        "#,
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await?;

    Ok(request)
}

pub async fn update_friend_request_status(
    pool: &PgPool,
    request_id: i64,
    status: &str,
) -> Result<FriendRequest, AppError> {
    let request = sqlx::query_as::<_, FriendRequest>(
        r#"
        WITH updated AS (
            UPDATE friend_requests fr
            SET status = $2,
                responded_at = CASE WHEN $2 = 'pending' THEN NULL ELSE NOW() END,
                updated_at = NOW()
            WHERE fr.id = $1
            RETURNING fr.id, fr.from_user_id, fr.to_user_id, fr.status, fr.created_at, fr.updated_at
        )
        SELECT
            u.id,
            u.from_user_id,
            fu.username AS from_username,
            fu.display_name AS from_display_name,
            fu.avatar_url AS from_avatar_url,
            u.to_user_id,
            tu.username AS to_username,
            tu.display_name AS to_display_name,
            u.status,
            u.created_at,
            u.updated_at
        FROM updated u
        JOIN users fu ON fu.id = u.from_user_id
        JOIN users tu ON tu.id = u.to_user_id
        "#,
    )
    .bind(request_id)
    .bind(status)
    .fetch_one(pool)
    .await?;

    Ok(request)
}

pub async fn create_bidirectional_friendship(
    pool: &PgPool,
    user_a: i64,
    user_b: i64,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        INSERT INTO friends (id, user_id, friend_user_id)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, friend_user_id) DO NOTHING
        "#,
    )
    .bind(crate::auth::generate_id())
    .bind(user_a)
    .bind(user_b)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO friends (id, user_id, friend_user_id)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, friend_user_id) DO NOTHING
        "#,
    )
    .bind(crate::auth::generate_id())
    .bind(user_b)
    .bind(user_a)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn list_friends(pool: &PgPool, actor_user_id: i64) -> Result<Vec<Friend>, AppError> {
    let friends = sqlx::query_as::<_, Friend>(
        r#"
        SELECT
            f.id,
            f.user_id,
            f.friend_user_id,
            u.username AS friend_username,
            u.display_name AS friend_display_name,
            u.avatar_url AS friend_avatar_url,
            f.created_at
        FROM friends f
        JOIN users u ON u.id = f.friend_user_id
        WHERE f.user_id = $1
        ORDER BY f.created_at DESC
        "#,
    )
    .bind(actor_user_id)
    .fetch_all(pool)
    .await?;

    Ok(friends)
}
