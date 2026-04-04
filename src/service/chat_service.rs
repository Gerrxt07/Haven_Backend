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
    repository::{chat_repository, e2ee_repository},
    service::realtime_service::RealtimeService,
    state::AppState,
};
use validator::Validate;

#[derive(Clone)]
pub struct ChatService {
    state: AppState,
}

impl ChatService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn create_server(&self, payload: CreateServerRequest) -> Result<Server, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if payload.owner_user_id <= 0 {
            return Err(AppError::Validation(
                "owner_user_id must be > 0".to_string(),
            ));
        }

        if !chat_repository::user_exists(&self.state.pg_pool, payload.owner_user_id).await? {
            return Err(AppError::BadRequest(
                "owner user does not exist".to_string(),
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

        let server = chat_repository::create_server(
            &self.state.pg_pool,
            chat_repository::NewServer {
                id: generate_id(),
                owner_user_id: payload.owner_user_id,
                name: payload.name.trim().to_string(),
                slug,
                description: payload.description,
                icon_url: payload.icon_url,
                is_public: payload.is_public.unwrap_or(true),
            },
        )
        .await?;

        chat_repository::add_server_owner_member(
            &self.state.pg_pool,
            generate_id(),
            server.id,
            server.owner_user_id,
        )
        .await?;

        Ok(server)
    }

    pub async fn create_channel(
        &self,
        server_id: i64,
        payload: CreateChannelRequest,
    ) -> Result<Channel, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if server_id <= 0 {
            return Err(AppError::Validation("server_id must be > 0".to_string()));
        }

        if let Some(actor_user_id) = payload.actor_user_id {
            if actor_user_id <= 0 {
                return Err(AppError::Validation(
                    "actor_user_id must be > 0".to_string(),
                ));
            }

            let is_member =
                chat_repository::is_server_member(&self.state.pg_pool, server_id, actor_user_id)
                    .await?;
            if !is_member {
                return Err(AppError::Forbidden);
            }
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

        chat_repository::create_channel(
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
        .await
    }

    pub async fn list_channels(
        &self,
        server_id: i64,
        query: PaginationQuery,
    ) -> Result<Vec<Channel>, AppError> {
        let limit = query.limit.unwrap_or(50).clamp(1, 100);
        chat_repository::list_channels(&self.state.pg_pool, server_id, query.before, limit).await
    }

    pub async fn create_message(
        &self,
        channel_id: i64,
        payload: CreateMessageRequest,
    ) -> Result<Message, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if channel_id <= 0 {
            return Err(AppError::Validation("channel_id must be > 0".to_string()));
        }

        if payload.author_user_id <= 0 {
            return Err(AppError::Validation(
                "author_user_id must be > 0".to_string(),
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

        let is_member = chat_repository::is_channel_member(
            &self.state.pg_pool,
            channel_id,
            payload.author_user_id,
        )
        .await?;
        if !is_member {
            return Err(AppError::Forbidden);
        }

        let message = chat_repository::create_message(
            &self.state.pg_pool,
            chat_repository::NewMessage {
                id: generate_id(),
                channel_id,
                author_user_id: payload.author_user_id,
                content: content_to_store,
                is_encrypted,
                ciphertext,
                nonce,
                aad,
                algorithm,
            },
        )
        .await?;

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
            Some(message.author_user_id),
            Some(channel_id.to_string()),
            serde_json::json!({
                "message_id": message.id,
                "channel_id": message.channel_id,
                "author_user_id": message.author_user_id,
                "is_encrypted": message.is_encrypted,
                "created_at": message.created_at,
            }),
        );

        let realtime_service = RealtimeService::new(self.state.clone());
        let _ = realtime_service.publish_with_fanout(event).await;

        Ok(message)
    }

    pub async fn list_messages(
        &self,
        channel_id: i64,
        query: PaginationQuery,
    ) -> Result<Vec<Message>, AppError> {
        if channel_id <= 0 {
            return Err(AppError::Validation("channel_id must be > 0".to_string()));
        }

        if let Some(before) = query.before {
            if before <= 0 {
                return Err(AppError::Validation(
                    "before cursor must be > 0".to_string(),
                ));
            }
        }

        let limit = query.limit.unwrap_or(50).clamp(1, 100);
        chat_repository::list_messages(&self.state.pg_pool, channel_id, query.before, limit).await
    }

    pub async fn create_channel_direct(
        &self,
        payload: crate::domain::chat::CreateChannelDirectRequest,
    ) -> Result<Channel, AppError> {
        let request = CreateChannelRequest {
            actor_user_id: Some(payload.actor_user_id),
            name: payload.name,
            topic: payload.topic,
            channel_type: payload.channel_type,
            position: payload.position,
            is_private: payload.is_private,
        };

        self.create_channel(payload.server_id, request).await
    }

    pub async fn create_message_direct(
        &self,
        payload: crate::domain::chat::CreateMessageDirectRequest,
    ) -> Result<Message, AppError> {
        let request = CreateMessageRequest {
            author_user_id: payload.author_user_id,
            content: payload.content,
            ciphertext: payload.ciphertext,
            nonce: payload.nonce,
            aad: payload.aad,
            algorithm: payload.algorithm,
            recipient_key_boxes: payload.recipient_key_boxes,
        };

        self.create_message(payload.channel_id, request).await
    }
}
