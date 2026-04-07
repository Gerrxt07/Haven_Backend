pub mod auth;
pub mod chat;
pub mod e2ee;
pub mod friends;
pub mod health;
pub mod users;

use axum::Router;

pub fn router() -> Router<crate::state::AppState> {
    Router::new()
        .merge(auth::router())
        .merge(chat::router())
        .merge(e2ee::router())
        .merge(friends::router())
        .merge(health::router())
        .merge(users::router())
}
