use crate::{
    domain::chat::{Channel, Message, Server},
    error::AppError,
};
use sqlx::PgPool;

pub struct NewServer {
    pub id: i64,
    pub owner_user_id: i64,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub is_public: bool,
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

pub async fn create_server(pool: &PgPool, input: NewServer) -> Result<Server, AppError> {
    let server = sqlx::query_as::<_, Server>(
        r#"
        INSERT INTO servers (id, owner_user_id, name, slug, description, icon_url, is_public)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, owner_user_id, name, slug, description, icon_url, is_public, created_at, updated_at
        "#,
    )
    .bind(input.id)
    .bind(input.owner_user_id)
    .bind(input.name)
    .bind(input.slug)
    .bind(input.description)
    .bind(input.icon_url)
    .bind(input.is_public)
    .fetch_one(pool)
    .await;

    match server {
        Ok(s) => Ok(s),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            Err(AppError::Conflict("server slug already exists".to_string()))
        }
        Err(err) => Err(AppError::Database(err)),
    }
}

pub async fn user_exists(pool: &PgPool, user_id: i64) -> Result<bool, AppError> {
    let exists = sqlx::query_scalar::<_, i64>("SELECT 1 FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .is_some();

    Ok(exists)
}

pub async fn add_server_owner_member(
    pool: &PgPool,
    id: i64,
    server_id: i64,
    user_id: i64,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO members (id, server_id, user_id, role)
        VALUES ($1, $2, $3, 'owner')
        ON CONFLICT (server_id, user_id) DO NOTHING
        "#,
    )
    .bind(id)
    .bind(server_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
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
