use crate::{
    auth::generate_id,
    domain::{
        friends::{Friend, FriendRequest, SendFriendRequest},
        realtime::RealtimeEvent,
    },
    error::AppError,
    repository::friends_repository,
    service::realtime_service::RealtimeService,
    state::AppState,
};
use validator::Validate;

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

        if friends_repository::has_pending_request_between(&self.state.pg_pool, actor_user_id, target.0)
            .await?
        {
            return Err(AppError::Conflict(
                "a pending friend request already exists".to_string(),
            ));
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
        friends_repository::list_incoming_pending(&self.state.pg_pool, actor_user_id).await
    }

    pub async fn list_outgoing(&self, actor_user_id: i64) -> Result<Vec<FriendRequest>, AppError> {
        friends_repository::list_outgoing_pending(&self.state.pg_pool, actor_user_id).await
    }

    pub async fn list_friends(&self, actor_user_id: i64) -> Result<Vec<Friend>, AppError> {
        friends_repository::list_friends(&self.state.pg_pool, actor_user_id).await
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

        let maybe_friend = friends_repository::get_friend_row(
            &self.state.pg_pool,
            updated.from_user_id,
            updated.to_user_id,
        )
        .await?;

        let event = RealtimeEvent::new(
            "friend_request_accepted",
            Some(actor_user_id),
            None,
            serde_json::json!({
                "request": updated,
                "friend": maybe_friend,
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
}
