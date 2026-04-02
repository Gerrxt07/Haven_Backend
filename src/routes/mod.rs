mod auth;
mod health;
mod users;

use axum::Router;

pub fn router() -> Router<crate::state::AppState> {
    Router::new()
        .merge(auth::router())
        .merge(health::router())
        .merge(users::router())
}
