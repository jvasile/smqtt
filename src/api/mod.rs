use axum::{
    routing::{delete, get, post},
    Router,
};

use crate::state::AppState;

mod admin;
mod auth;
mod exchange;
pub mod extractors;
mod register;
mod relationships;

pub fn router(state: AppState) -> Router {
    Router::new()
        // Registration and auth
        .route("/register",      post(register::register))
        .route("/auth/challenge", get(auth::challenge))
        .route("/auth/verify",   post(auth::verify))
        // Key exchange
        .route("/exchange",                    post(exchange::initiate))
        .route("/exchange/:exchange_id",        get(exchange::get))
        .route("/exchange/:exchange_id/respond", post(exchange::respond))
        // Relationships (require valid JWT)
        .route("/relationships",               post(relationships::create))
        .route("/relationships",               get(relationships::list))
        .route("/relationships/:id",           delete(relationships::revoke))
        // Admin (require admin key)
        .route("/admin/registration-tokens",   post(admin::create_registration_token))
        .route("/admin/users/:user_id/suspend",   post(admin::suspend_user))
        .route("/admin/users/:user_id/unsuspend", post(admin::unsuspend_user))
        .with_state(state)
}
