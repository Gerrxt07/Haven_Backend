use axum::Router;

pub fn router() -> Router<crate::state::AppState> {
    crate::transport::http::router().merge(crate::transport::ws::router())
}
