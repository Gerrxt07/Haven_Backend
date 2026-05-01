use crate::{
    domain::chat::{Channel, DmMessage, DmThread, DmThreadSummary, Message, Server},
    error::AppError,
};
use sqlx::PgPool;

pub struct NewServer {
    pub owner_user_id: i64,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub is_public: bool,
}

pub struct ServerWithOwnerMemberIds {
    pub server_id: i64,
    pub member_id: i64,
}

pub struct NewChannel {
    pub id: i64,
    pub server_id: i64,
    pub name: String,
    pub topic: Option<String>,
    pub channel_type: String,
    pub position: i32,
    pub is_private: bool,
}

pub struct NewMessage {
    pub id: i64,
    pub channel_id: i64,
    pub author_user_id: i64,
    pub content: String,
    pub is_encrypted: bool,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub aad: Option<String>,
    pub algorithm: Option<String>,
}

pub struct NewDmThread {
    pub id: i64,
    pub user_a_id: i64,
    pub user_b_id: i64,
    pub created_by_user_id: i64,
}

pub struct NewDmMessage {
    pub id: i64,
    pub thread_id: i64,
    pub author_user_id: i64,
    pub content: String,
    pub is_encrypted: bool,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
    pub aad: Option<String>,
    pub algorithm: Option<String>,
}

pub async fn create_server_with_owner_member(
    pool: &PgPool,
    ids: ServerWithOwnerMemberIds,
    input: NewServer,
) -> Result<Server, AppError> {
    let server = sqlx::query_as::<_, Server>(
        r#"
        WITH inserted_server AS (
            INSERT INTO servers (id, owner_user_id, name, slug, description, icon_url, is_public)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, owner_user_id, name, slug, description, icon_url, is_public, created_at, updated_at
        ), inserted_member AS (
            INSERT INTO members (id, server_id, user_id, role)
            SELECT $8, s.id, s.owner_user_id, 'owner'
            FROM inserted_server s
            ON CONFLICT (server_id, user_id) DO NOTHING
        )
        SELECT id, owner_user_id, name, slug, description, icon_url, is_public, created_at, updated_at
        FROM inserted_server
        "#,
    )
    .bind(ids.server_id)
    .bind(input.owner_user_id)
    .bind(input.name)
    .bind(input.slug)
    .bind(input.description)
    .bind(input.icon_url)
    .bind(input.is_public)
    .bind(ids.member_id)
    .fetch_one(pool)
    .await;

    match server {
        Ok(s) => Ok(s),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            Err(AppError::Conflict("server slug already exists".to_string()))
        }
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23503") => Err(
            AppError::BadRequest("owner user does not exist".to_string()),
        ),
        Err(err) => Err(AppError::Database(err)),
    }
}

pub async fn is_server_member(
    pool: &PgPool,
    server_id: i64,
    user_id: i64,
) -> Result<bool, AppError> {
    let exists =
        sqlx::query_scalar::<_, i64>("SELECT 1 FROM members WHERE server_id = $1 AND user_id = $2")
            .bind(server_id)
            .bind(user_id)
            .fetch_optional(pool)
            .await?
            .is_some();

    Ok(exists)
}

pub async fn is_channel_member(
    pool: &PgPool,
    channel_id: i64,
    user_id: i64,
) -> Result<bool, AppError> {
    let exists = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT 1
        FROM channels c
        JOIN members m ON m.server_id = c.server_id
        WHERE c.id = $1 AND m.user_id = $2
        "#,
    )
    .bind(channel_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .is_some();

    Ok(exists)
}

pub async fn create_channel(pool: &PgPool, input: NewChannel) -> Result<Channel, AppError> {
    let channel = sqlx::query_as::<_, Channel>(
        r#"
        INSERT INTO channels (id, server_id, name, topic, channel_type, position, is_private)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, server_id, name, topic, channel_type, position, is_private, created_at, updated_at
        "#,
    )
    .bind(input.id)
    .bind(input.server_id)
    .bind(input.name)
    .bind(input.topic)
    .bind(input.channel_type)
    .bind(input.position)
    .bind(input.is_private)
    .fetch_one(pool)
    .await;

    match channel {
        Ok(c) => Ok(c),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => Err(
            AppError::Conflict("channel name already exists in server".to_string()),
        ),
        Err(err) => Err(AppError::Database(err)),
    }
}

pub async fn list_channels(
    pool: &PgPool,
    server_id: i64,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<Channel>, AppError> {
    let channels = sqlx::query_as::<_, Channel>(
        r#"
        SELECT id, server_id, name, topic, channel_type, position, is_private, created_at, updated_at
        FROM channels
        WHERE server_id = $1
          AND ($2::BIGINT IS NULL OR id < $2)
        ORDER BY id DESC
        LIMIT $3
        "#,
    )
    .bind(server_id)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(channels)
}

pub async fn create_message(pool: &PgPool, input: NewMessage) -> Result<Message, AppError> {
    let message = sqlx::query_as::<_, Message>(
        r#"
        INSERT INTO messages (
            id, channel_id, author_user_id, content,
            is_encrypted, ciphertext, nonce, aad, algorithm
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING
            id, channel_id, author_user_id,
            (SELECT avatar_url FROM users WHERE id = author_user_id) AS author_avatar_url,
            content,
            is_encrypted, ciphertext, nonce, aad, algorithm,
            edited_at, deleted_at, created_at, updated_at
        "#,
    )
    .bind(input.id)
    .bind(input.channel_id)
    .bind(input.author_user_id)
    .bind(input.content)
    .bind(input.is_encrypted)
    .bind(input.ciphertext)
    .bind(input.nonce)
    .bind(input.aad)
    .bind(input.algorithm)
    .fetch_one(pool)
    .await?;

    Ok(message)
}

pub async fn list_messages(
    pool: &PgPool,
    channel_id: i64,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<Message>, AppError> {
    let messages = sqlx::query_as::<_, Message>(
        r#"
        SELECT
                        m.id,
                        m.channel_id,
                        m.author_user_id,
                        u.avatar_url AS author_avatar_url,
                        m.content,
            m.is_encrypted, m.ciphertext, m.nonce, m.aad, m.algorithm,
            m.edited_at, m.deleted_at, m.created_at, m.updated_at
                FROM messages m
                LEFT JOIN users u ON u.id = m.author_user_id
                WHERE m.channel_id = $1
                    AND m.deleted_at IS NULL
                    AND ($2::BIGINT IS NULL OR m.id < $2)
                ORDER BY m.id DESC
        LIMIT $3
        "#,
    )
    .bind(channel_id)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(messages)
}

pub async fn create_or_get_dm_thread(
    pool: &PgPool,
    input: NewDmThread,
) -> Result<DmThread, AppError> {
    if let Some(thread) = find_dm_thread_by_pair(pool, input.user_a_id, input.user_b_id).await? {
        return Ok(thread);
    }

    let thread = sqlx::query_as::<_, DmThread>(
        r#"
        INSERT INTO dm_threads (id, user_a_id, user_b_id, created_by_user_id)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_a_id, user_b_id, created_by_user_id, created_at, updated_at
        "#,
    )
    .bind(input.id)
    .bind(input.user_a_id)
    .bind(input.user_b_id)
    .bind(input.created_by_user_id)
    .fetch_one(pool)
    .await;

    match thread {
        Ok(thread) => Ok(thread),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            find_dm_thread_by_pair(pool, input.user_a_id, input.user_b_id)
                .await?
                .ok_or_else(|| {
                    AppError::Conflict("direct message thread already exists".to_string())
                })
        }
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("42703") => {
            tracing::warn!(
                event = "dm.thread.create.legacy_schema",
                db_code = ?db_err.code(),
                db_message = %db_err.message(),
                "falling back to legacy dm_threads insert"
            );
            create_dm_thread_legacy_schema(pool, input).await
        }
        Err(err) => Err(AppError::Database(err)),
    }
}

async fn create_dm_thread_legacy_schema(
    pool: &PgPool,
    input: NewDmThread,
) -> Result<DmThread, AppError> {
    let thread = sqlx::query_as::<_, DmThread>(
        r#"
        INSERT INTO dm_threads (id, user_a_id, user_b_id)
        VALUES ($1, $2, $3)
        RETURNING id, user_a_id, user_b_id, user_a_id AS created_by_user_id, created_at, updated_at
        "#,
    )
    .bind(input.id)
    .bind(input.user_a_id)
    .bind(input.user_b_id)
    .fetch_one(pool)
    .await;

    match thread {
        Ok(thread) => Ok(thread),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            find_dm_thread_by_pair(pool, input.user_a_id, input.user_b_id)
                .await?
                .ok_or_else(|| {
                    AppError::Conflict("direct message thread already exists".to_string())
                })
        }
        Err(sqlx::Error::Database(db_err)) => {
            tracing::error!(
                event = "dm.thread.create.database_error",
                db_code = ?db_err.code(),
                db_message = %db_err.message(),
                "failed to create direct message thread"
            );
            Err(AppError::Database(sqlx::Error::Database(db_err)))
        }
        Err(err) => Err(AppError::Database(err)),
    }
}

async fn find_dm_thread_by_pair(
    pool: &PgPool,
    user_a_id: i64,
    user_b_id: i64,
) -> Result<Option<DmThread>, AppError> {
    let thread = sqlx::query_as::<_, DmThread>(
        r#"
        SELECT id, user_a_id, user_b_id, user_a_id AS created_by_user_id, created_at, updated_at
        FROM dm_threads
        WHERE user_a_id = $1
          AND user_b_id = $2
        ORDER BY id
        LIMIT 1
        "#,
    )
    .bind(user_a_id)
    .bind(user_b_id)
    .fetch_optional(pool)
    .await?;

    Ok(thread)
}

pub async fn is_dm_participant(
    pool: &PgPool,
    thread_id: i64,
    user_id: i64,
) -> Result<bool, AppError> {
    let exists = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT 1
        FROM dm_threads
        WHERE id = $1
          AND (user_a_id = $2 OR user_b_id = $2)
        "#,
    )
    .bind(thread_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .is_some();

    Ok(exists)
}

pub async fn list_dm_threads(
    pool: &PgPool,
    actor_user_id: i64,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<DmThreadSummary>, AppError> {
    let rows = sqlx::query_as::<_, DmThreadSummary>(
        r#"
        SELECT
            t.id,
            CASE WHEN t.user_a_id = $1 THEN t.user_b_id ELSE t.user_a_id END AS peer_user_id,
            u.username AS peer_username,
            u.display_name AS peer_display_name,
            u.avatar_url AS peer_avatar_url,
            lm.last_message_preview,
            lm.last_message_at,
            t.created_at,
            t.updated_at
        FROM dm_threads t
        JOIN users u ON u.id = CASE WHEN t.user_a_id = $1 THEN t.user_b_id ELSE t.user_a_id END
        LEFT JOIN LATERAL (
            SELECT
                CASE
                    WHEN m.is_encrypted THEN '[e2ee]'
                    ELSE LEFT(m.content, 120)
                END AS last_message_preview,
                m.created_at AS last_message_at
            FROM dm_messages m
            WHERE m.thread_id = t.id
              AND m.deleted_at IS NULL
            ORDER BY m.id DESC
            LIMIT 1
        ) lm ON TRUE
        WHERE (t.user_a_id = $1 OR t.user_b_id = $1)
          AND ($2::BIGINT IS NULL OR t.id < $2)
        ORDER BY COALESCE(lm.last_message_at, t.updated_at) DESC, t.id DESC
        LIMIT $3
        "#,
    )
    .bind(actor_user_id)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn get_dm_thread_summary(
    pool: &PgPool,
    actor_user_id: i64,
    thread_id: i64,
) -> Result<Option<DmThreadSummary>, AppError> {
    let row = sqlx::query_as::<_, DmThreadSummary>(
        r#"
        SELECT
            t.id,
            CASE WHEN t.user_a_id = $1 THEN t.user_b_id ELSE t.user_a_id END AS peer_user_id,
            u.username AS peer_username,
            u.display_name AS peer_display_name,
            u.avatar_url AS peer_avatar_url,
            lm.last_message_preview,
            lm.last_message_at,
            t.created_at,
            t.updated_at
        FROM dm_threads t
        JOIN users u ON u.id = CASE WHEN t.user_a_id = $1 THEN t.user_b_id ELSE t.user_a_id END
        LEFT JOIN LATERAL (
            SELECT
                CASE
                    WHEN m.is_encrypted THEN '[e2ee]'
                    ELSE LEFT(m.content, 120)
                END AS last_message_preview,
                m.created_at AS last_message_at
            FROM dm_messages m
            WHERE m.thread_id = t.id
              AND m.deleted_at IS NULL
            ORDER BY m.id DESC
            LIMIT 1
        ) lm ON TRUE
        WHERE t.id = $2
          AND (t.user_a_id = $1 OR t.user_b_id = $1)
        "#,
    )
    .bind(actor_user_id)
    .bind(thread_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

pub async fn create_dm_message(pool: &PgPool, input: NewDmMessage) -> Result<DmMessage, AppError> {
    let message = sqlx::query_as::<_, DmMessage>(
        r#"
        WITH inserted AS (
            INSERT INTO dm_messages (
                id, thread_id, author_user_id, content,
                is_encrypted, ciphertext, nonce, aad, algorithm
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING
                id, thread_id, author_user_id, content,
                is_encrypted, ciphertext, nonce, aad, algorithm,
                edited_at, deleted_at, created_at, updated_at
        ),
        bumped AS (
            UPDATE dm_threads
            SET updated_at = NOW()
            WHERE id = $2
        )
        SELECT
            i.id,
            i.thread_id,
            i.author_user_id,
            (SELECT avatar_url FROM users WHERE id = i.author_user_id) AS author_avatar_url,
            i.content,
            i.is_encrypted,
            i.ciphertext,
            i.nonce,
            i.aad,
            i.algorithm,
            i.edited_at,
            i.deleted_at,
            i.created_at,
            i.updated_at
        FROM inserted i
        "#,
    )
    .bind(input.id)
    .bind(input.thread_id)
    .bind(input.author_user_id)
    .bind(input.content)
    .bind(input.is_encrypted)
    .bind(input.ciphertext)
    .bind(input.nonce)
    .bind(input.aad)
    .bind(input.algorithm)
    .fetch_one(pool)
    .await?;

    Ok(message)
}

pub async fn list_dm_messages(
    pool: &PgPool,
    thread_id: i64,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<DmMessage>, AppError> {
    let messages = sqlx::query_as::<_, DmMessage>(
        r#"
        SELECT
            m.id,
            m.thread_id,
            m.author_user_id,
            u.avatar_url AS author_avatar_url,
            m.content,
            m.is_encrypted,
            m.ciphertext,
            m.nonce,
            m.aad,
            m.algorithm,
            m.edited_at,
            m.deleted_at,
            m.created_at,
            m.updated_at
        FROM dm_messages m
        LEFT JOIN users u ON u.id = m.author_user_id
        WHERE m.thread_id = $1
          AND m.deleted_at IS NULL
          AND ($2::BIGINT IS NULL OR m.id < $2)
        ORDER BY m.id DESC
        LIMIT $3
        "#,
    )
    .bind(thread_id)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(messages)
}
