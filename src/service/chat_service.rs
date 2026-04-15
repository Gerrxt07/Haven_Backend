use crate::{
    auth::generate_id,
    domain::{
        chat::{
            Channel, CreateChannelRequest, CreateMessageRequest, CreateServerRequest, Message,
            PaginationQuery, Server,
        },
        realtime::RealtimeEvent,
    },
    error::AppError,
    repository::{cache_repository, chat_repository, e2ee_repository},
    service::realtime_service::RealtimeService,
    state::AppState,
};
use tracing::info;
use validator::Validate;

const MEMBERSHIP_CACHE_TTL_SECONDS: u64 = 120;
const CHANNEL_LIST_CACHE_TTL_SECONDS: u64 = 300;
const MESSAGE_LIST_CACHE_TTL_SECONDS: u64 = 120;

#[derive(Clone)]
pub struct ChatService {
    state: AppState,
}

impl ChatService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn create_server(
        &self,
        actor_user_id: i64,
        payload: CreateServerRequest,
    ) -> Result<Server, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if actor_user_id <= 0 {
            return Err(AppError::Validation(
                "authenticated user id must be > 0".to_string(),
            ));
        }

        let slug = payload.slug.trim().to_lowercase();
        if !slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(AppError::Validation(
                "slug must contain only [a-z0-9-]".to_string(),
            ));
        }

        let server = chat_repository::create_server_with_owner_member(
            &self.state.pg_pool,
            chat_repository::ServerWithOwnerMemberIds {
                server_id: generate_id(),
                member_id: generate_id(),
            },
            chat_repository::NewServer {
                owner_user_id: actor_user_id,
                name: payload.name.trim().to_string(),
                slug,
                description: payload.description,
                icon_url: payload.icon_url,
                is_public: payload.is_public.unwrap_or(true),
            },
        )
        .await?;

        let server_membership_key =
            format!("cache:chat:member:server:{}:user:{}", server.id, actor_user_id);
        cache_repository::set_json(
            &self.state.redis_pool,
            &server_membership_key,
            &true,
            MEMBERSHIP_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(server)
    }

    pub async fn create_channel(
        &self,
        actor_user_id: i64,
        server_id: i64,
        payload: CreateChannelRequest,
    ) -> Result<Channel, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if server_id <= 0 {
            return Err(AppError::Validation("server_id must be > 0".to_string()));
        }

        if actor_user_id <= 0 {
            return Err(AppError::Validation(
                "authenticated user id must be > 0".to_string(),
            ));
        }

        let is_member = self
            .is_server_member_cached(server_id, actor_user_id)
            .await?;
        if !is_member {
            return Err(AppError::Forbidden);
        }

        let channel_type = payload.channel_type.unwrap_or_else(|| "text".to_string());
        if channel_type != "text" && channel_type != "voice" && channel_type != "announcement" {
            return Err(AppError::Validation("invalid channel_type".to_string()));
        }

        if let Some(topic) = &payload.topic {
            if topic.len() > 500 {
                return Err(AppError::Validation("topic too long".to_string()));
            }
        }

        let channel = chat_repository::create_channel(
            &self.state.pg_pool,
            chat_repository::NewChannel {
                id: generate_id(),
                server_id,
                name: payload.name.trim().to_string(),
                topic: payload.topic,
                channel_type,
                position: payload.position.unwrap_or(0),
                is_private: payload.is_private.unwrap_or(false),
            },
        )
        .await?;

        let index_key = format!("cache:chat:channels:index:{server_id}");
        cache_repository::invalidate_indexed_keys(&self.state.redis_pool, &index_key).await?;

        Ok(channel)
    }

    pub async fn list_channels(
        &self,
        actor_user_id: i64,
        server_id: i64,
        query: PaginationQuery,
    ) -> Result<Vec<Channel>, AppError> {
        if actor_user_id <= 0 {
            return Err(AppError::Validation(
                "authenticated user id must be > 0".to_string(),
            ));
        }
        let is_member = self
            .is_server_member_cached(server_id, actor_user_id)
            .await?;
        if !is_member {
            return Err(AppError::Forbidden);
        }

        let limit = query.limit.unwrap_or(50).clamp(1, 100);
        let before = query.before;
        let before_token = before.unwrap_or(0);
        let cache_key = format!("cache:chat:channels:{server_id}:{before_token}:{limit}");

        if let Some(cached) = cache_repository::get_json::<Vec<Channel>>(
            &self.state.redis_pool,
            &cache_key,
        )
        .await?
        {
            return Ok(cached);
        }

        let channels =
            chat_repository::list_channels(&self.state.pg_pool, server_id, before, limit).await?;

        let index_key = format!("cache:chat:channels:index:{server_id}");
        cache_repository::set_json_indexed(
            &self.state.redis_pool,
            &index_key,
            &cache_key,
            &channels,
            CHANNEL_LIST_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(channels)
    }

    pub async fn create_message(
        &self,
        actor_user_id: i64,
        channel_id: i64,
        payload: CreateMessageRequest,
    ) -> Result<Message, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if channel_id <= 0 {
            return Err(AppError::Validation("channel_id must be > 0".to_string()));
        }

        if actor_user_id <= 0 {
            return Err(AppError::Validation(
                "authenticated user id must be > 0".to_string(),
            ));
        }

        let is_encrypted = payload.ciphertext.is_some() || payload.nonce.is_some();

        let (content_to_store, ciphertext, nonce, aad, algorithm, recipient_key_boxes) =
            if is_encrypted {
                let ciphertext = payload
                    .ciphertext
                    .as_ref()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .ok_or(AppError::Validation(
                        "ciphertext is required for e2ee message".to_string(),
                    ))?;

                let nonce = payload
                    .nonce
                    .as_ref()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .ok_or(AppError::Validation(
                        "nonce is required for e2ee message".to_string(),
                    ))?;

                let recipient_key_boxes =
                    payload
                        .recipient_key_boxes
                        .clone()
                        .ok_or(AppError::Validation(
                            "recipient_key_boxes are required for e2ee message".to_string(),
                        ))?;

                if recipient_key_boxes.is_empty() {
                    return Err(AppError::Validation(
                        "recipient_key_boxes cannot be empty".to_string(),
                    ));
                }

                for box_item in &recipient_key_boxes {
                    if box_item.recipient_user_id <= 0 {
                        return Err(AppError::Validation(
                            "recipient_user_id must be > 0".to_string(),
                        ));
                    }
                    if box_item.encrypted_message_key.trim().is_empty() {
                        return Err(AppError::Validation(
                            "encrypted_message_key must not be empty".to_string(),
                        ));
                    }
                }

                (
                    "[e2ee]".to_string(),
                    Some(ciphertext),
                    Some(nonce),
                    payload.aad,
                    Some(
                        payload
                            .algorithm
                            .unwrap_or_else(|| "xchacha20poly1305".to_string()),
                    ),
                    Some(recipient_key_boxes),
                )
            } else {
                let content = payload
                    .content
                    .as_ref()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .ok_or(AppError::Validation(
                        "content must not be empty".to_string(),
                    ))?;

                if content
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t')
                {
                    return Err(AppError::Validation(
                        "content contains invalid control characters".to_string(),
                    ));
                }

                (content, None, None, None, None, None)
            };

        let is_member = self
            .is_channel_member_cached(channel_id, actor_user_id)
            .await?;
        if !is_member {
            return Err(AppError::Forbidden);
        }

        let message = chat_repository::create_message(
            &self.state.pg_pool,
            chat_repository::NewMessage {
                id: generate_id(),
                channel_id,
                author_user_id: actor_user_id,
                content: content_to_store,
                is_encrypted,
                ciphertext,
                nonce,
                aad,
                algorithm,
            },
        )
        .await?;

        let message_index_key = format!("cache:chat:messages:index:{channel_id}");
        cache_repository::invalidate_indexed_keys(&self.state.redis_pool, &message_index_key)
            .await?;

        info!(
            event = "chat.message.created",
            channel_id = message.channel_id,
            message_id = message.id,
            author_user_id = message.author_user_id,
            has_author_avatar_url = message.author_avatar_url.is_some(),
            "chat message created"
        );

        if let Some(recipient_key_boxes) = recipient_key_boxes {
            let rows = recipient_key_boxes
                .into_iter()
                .map(|box_item| crate::domain::e2ee::NewMessageRecipientKey {
                    message_id: message.id,
                    recipient_user_id: box_item.recipient_user_id,
                    encrypted_message_key: box_item.encrypted_message_key,
                    one_time_prekey_id: box_item.one_time_prekey_id,
                })
                .collect::<Vec<_>>();

            e2ee_repository::insert_message_recipient_keys(&self.state.pg_pool, rows).await?;
        }

        let event = RealtimeEvent::new(
            "new_message",
            Some(actor_user_id),
            Some(channel_id.to_string()),
            serde_json::json!({
                "message_id": message.id,
                "channel_id": message.channel_id,
                "author_user_id": message.author_user_id,
                "author_avatar_url": message.author_avatar_url,
                "is_encrypted": message.is_encrypted,
                "created_at": message.created_at,
            }),
        );

        info!(
            event = "chat.message.realtime_published",
            channel_id = message.channel_id,
            message_id = message.id,
            author_user_id = message.author_user_id,
            has_author_avatar_url = message.author_avatar_url.is_some(),
            "chat realtime event published with author avatar metadata"
        );

        let realtime_service = RealtimeService::new(self.state.clone());
        let _ = realtime_service.publish_with_fanout(event).await;

        Ok(message)
    }

    pub async fn list_messages(
        &self,
        actor_user_id: i64,
        channel_id: i64,
        query: PaginationQuery,
    ) -> Result<Vec<Message>, AppError> {
        if actor_user_id <= 0 {
            return Err(AppError::Validation(
                "authenticated user id must be > 0".to_string(),
            ));
        }
        if channel_id <= 0 {
            return Err(AppError::Validation("channel_id must be > 0".to_string()));
        }

        let is_member = self
            .is_channel_member_cached(channel_id, actor_user_id)
            .await?;
        if !is_member {
            return Err(AppError::Forbidden);
        }

        if let Some(before) = query.before {
            if before <= 0 {
                return Err(AppError::Validation(
                    "before cursor must be > 0".to_string(),
                ));
            }
        }

        let limit = query.limit.unwrap_or(50).clamp(1, 100);
        let before = query.before;
        let before_token = before.unwrap_or(0);
        let cache_key = format!("cache:chat:messages:{channel_id}:{before_token}:{limit}");

        if let Some(cached) = cache_repository::get_json::<Vec<Message>>(
            &self.state.redis_pool,
            &cache_key,
        )
        .await?
        {
            return Ok(cached);
        }

        let messages =
            chat_repository::list_messages(&self.state.pg_pool, channel_id, before, limit).await?;

        let index_key = format!("cache:chat:messages:index:{channel_id}");
        cache_repository::set_json_indexed(
            &self.state.redis_pool,
            &index_key,
            &cache_key,
            &messages,
            MESSAGE_LIST_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(messages)
    }

    pub async fn create_channel_direct(
        &self,
        actor_user_id: i64,
        payload: crate::domain::chat::CreateChannelDirectRequest,
    ) -> Result<Channel, AppError> {
        let request = CreateChannelRequest {
            name: payload.name,
            topic: payload.topic,
            channel_type: payload.channel_type,
            position: payload.position,
            is_private: payload.is_private,
        };

        self.create_channel(actor_user_id, payload.server_id, request)
            .await
    }

    pub async fn create_message_direct(
        &self,
        actor_user_id: i64,
        payload: crate::domain::chat::CreateMessageDirectRequest,
    ) -> Result<Message, AppError> {
        let request = CreateMessageRequest {
            content: payload.content,
            ciphertext: payload.ciphertext,
            nonce: payload.nonce,
            aad: payload.aad,
            algorithm: payload.algorithm,
            recipient_key_boxes: payload.recipient_key_boxes,
        };

        self.create_message(actor_user_id, payload.channel_id, request)
            .await
    }

    async fn is_server_member_cached(
        &self,
        server_id: i64,
        actor_user_id: i64,
    ) -> Result<bool, AppError> {
        let cache_key = format!("cache:chat:member:server:{server_id}:user:{actor_user_id}");
        if let Some(cached) = cache_repository::get_json::<bool>(&self.state.redis_pool, &cache_key)
            .await?
        {
            return Ok(cached);
        }

        let is_member =
            chat_repository::is_server_member(&self.state.pg_pool, server_id, actor_user_id)
                .await?;

        cache_repository::set_json(
            &self.state.redis_pool,
            &cache_key,
            &is_member,
            MEMBERSHIP_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(is_member)
    }

    async fn is_channel_member_cached(
        &self,
        channel_id: i64,
        actor_user_id: i64,
    ) -> Result<bool, AppError> {
        let cache_key = format!("cache:chat:member:channel:{channel_id}:user:{actor_user_id}");
        if let Some(cached) = cache_repository::get_json::<bool>(&self.state.redis_pool, &cache_key)
            .await?
        {
            return Ok(cached);
        }

        let is_member =
            chat_repository::is_channel_member(&self.state.pg_pool, channel_id, actor_user_id)
                .await?;

        cache_repository::set_json(
            &self.state.redis_pool,
            &cache_key,
            &is_member,
            MEMBERSHIP_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(is_member)
    }
}
