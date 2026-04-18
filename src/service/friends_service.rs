use crate::{
    auth::generate_id,
    domain::{
        friends::{Friend, FriendRequest, SendFriendRequest},
        realtime::RealtimeEvent,
    },
    error::AppError,
    repository::{cache_repository, friends_repository},
    service::realtime_service::RealtimeService,
    state::AppState,
};
use validator::Validate;

const FRIENDS_CACHE_TTL_SECONDS: u64 = 300;

#[derive(Clone)]
pub struct FriendsService {
    state: AppState,
}

impl FriendsService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn send_request(
        &self,
        actor_user_id: i64,
        payload: SendFriendRequest,
    ) -> Result<FriendRequest, AppError> {
        payload
            .validate()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        if actor_user_id <= 0 {
            return Err(AppError::Validation(
                "authenticated user id must be > 0".to_string(),
            ));
        }

        let username = payload.username.trim().to_lowercase();
        let target = friends_repository::find_user_by_username(&self.state.pg_pool, &username)
            .await?
            .ok_or(AppError::NotFound)?;

        if target.0 == actor_user_id {
            return Err(AppError::Conflict(
                "you cannot send a friend request to yourself".to_string(),
            ));
        }

        if friends_repository::are_friends(&self.state.pg_pool, actor_user_id, target.0).await? {
            return Err(AppError::Conflict("users are already friends".to_string()));
        }

        let request = friends_repository::create_friend_request(
            &self.state.pg_pool,
            friends_repository::NewFriendRequest {
                id: generate_id(),
                from_user_id: actor_user_id,
                to_user_id: target.0,
            },
        )
        .await?;

        self.invalidate_pending_cache_for(actor_user_id, target.0)
            .await?;

        let event = RealtimeEvent::new(
            "friend_request_received",
            Some(actor_user_id),
            None,
            serde_json::json!({ "request": request }),
        );
        let _ = RealtimeService::new(self.state.clone())
            .publish_with_fanout(event)
            .await;

        Ok(request)
    }

    pub async fn list_incoming(&self, actor_user_id: i64) -> Result<Vec<FriendRequest>, AppError> {
        let cache_key = format!("cache:friends:incoming:{actor_user_id}");
        if let Some(cached) =
            cache_repository::get_json::<Vec<FriendRequest>>(&self.state.redis_pool, &cache_key)
                .await?
        {
            return Ok(cached);
        }

        let requests =
            friends_repository::list_incoming_pending(&self.state.pg_pool, actor_user_id).await?;

        let index_key = format!("cache:friends:index:{actor_user_id}");
        cache_repository::set_json_indexed(
            &self.state.redis_pool,
            &index_key,
            &cache_key,
            &requests,
            FRIENDS_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(requests)
    }

    pub async fn list_outgoing(&self, actor_user_id: i64) -> Result<Vec<FriendRequest>, AppError> {
        let cache_key = format!("cache:friends:outgoing:{actor_user_id}");
        if let Some(cached) =
            cache_repository::get_json::<Vec<FriendRequest>>(&self.state.redis_pool, &cache_key)
                .await?
        {
            return Ok(cached);
        }

        let requests =
            friends_repository::list_outgoing_pending(&self.state.pg_pool, actor_user_id).await?;

        let index_key = format!("cache:friends:index:{actor_user_id}");
        cache_repository::set_json_indexed(
            &self.state.redis_pool,
            &index_key,
            &cache_key,
            &requests,
            FRIENDS_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(requests)
    }

    pub async fn list_friends(&self, actor_user_id: i64) -> Result<Vec<Friend>, AppError> {
        let cache_key = format!("cache:friends:list:{actor_user_id}");
        if let Some(cached) =
            cache_repository::get_json::<Vec<Friend>>(&self.state.redis_pool, &cache_key).await?
        {
            return Ok(cached);
        }

        let friends = friends_repository::list_friends(&self.state.pg_pool, actor_user_id).await?;

        let index_key = format!("cache:friends:index:{actor_user_id}");
        cache_repository::set_json_indexed(
            &self.state.redis_pool,
            &index_key,
            &cache_key,
            &friends,
            FRIENDS_CACHE_TTL_SECONDS,
        )
        .await?;

        Ok(friends)
    }

    pub async fn accept_request(
        &self,
        actor_user_id: i64,
        request_id: i64,
    ) -> Result<FriendRequest, AppError> {
        let request = friends_repository::get_friend_request_by_id(&self.state.pg_pool, request_id)
            .await?
            .ok_or(AppError::NotFound)?;

        if request.to_user_id != actor_user_id {
            return Err(AppError::Forbidden);
        }

        if request.status != "pending" {
            return Ok(request);
        }

        let updated = friends_repository::update_friend_request_status(
            &self.state.pg_pool,
            request_id,
            "accepted",
        )
        .await?;

        friends_repository::create_bidirectional_friendship(
            &self.state.pg_pool,
            updated.from_user_id,
            updated.to_user_id,
        )
        .await?;

        self.invalidate_pending_cache_for(updated.from_user_id, updated.to_user_id)
            .await?;
        self.invalidate_friends_cache_for(updated.from_user_id, updated.to_user_id)
            .await?;

        let event = RealtimeEvent::new(
            "friend_request_accepted",
            Some(actor_user_id),
            None,
            serde_json::json!({
                "request": updated,
            }),
        );
        let _ = RealtimeService::new(self.state.clone())
            .publish_with_fanout(event)
            .await;

        Ok(updated)
    }

    pub async fn decline_request(
        &self,
        actor_user_id: i64,
        request_id: i64,
    ) -> Result<FriendRequest, AppError> {
        let request = friends_repository::get_friend_request_by_id(&self.state.pg_pool, request_id)
            .await?
            .ok_or(AppError::NotFound)?;

        if request.to_user_id != actor_user_id {
            return Err(AppError::Forbidden);
        }

        if request.status != "pending" {
            return Ok(request);
        }

        let updated = friends_repository::update_friend_request_status(
            &self.state.pg_pool,
            request_id,
            "declined",
        )
        .await?;

        self.invalidate_pending_cache_for(updated.from_user_id, updated.to_user_id)
            .await?;

        let event = RealtimeEvent::new(
            "friend_request_declined",
            Some(actor_user_id),
            None,
            serde_json::json!({ "request": updated }),
        );
        let _ = RealtimeService::new(self.state.clone())
            .publish_with_fanout(event)
            .await;

        Ok(updated)
    }

    async fn invalidate_pending_cache_for(&self, user_a: i64, user_b: i64) -> Result<(), AppError> {
        let index_a = format!("cache:friends:index:{user_a}");
        let index_b = format!("cache:friends:index:{user_b}");
        cache_repository::invalidate_indexed_keys(&self.state.redis_pool, &index_a).await?;
        if user_a != user_b {
            cache_repository::invalidate_indexed_keys(&self.state.redis_pool, &index_b).await?;
        }
        Ok(())
    }

    async fn invalidate_friends_cache_for(&self, user_a: i64, user_b: i64) -> Result<(), AppError> {
        let index_a = format!("cache:friends:index:{user_a}");
        let index_b = format!("cache:friends:index:{user_b}");
        cache_repository::invalidate_indexed_keys(&self.state.redis_pool, &index_a).await?;
        if user_a != user_b {
            cache_repository::invalidate_indexed_keys(&self.state.redis_pool, &index_b).await?;
        }
        Ok(())
    }
}
