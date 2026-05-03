use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Error::NotFound       => (StatusCode::NOT_FOUND,            self.to_string()),
            Error::Unauthorized   => (StatusCode::UNAUTHORIZED,         self.to_string()),
            Error::Forbidden      => (StatusCode::FORBIDDEN,            self.to_string()),
            Error::BadRequest(m)  => (StatusCode::BAD_REQUEST,          m.clone()),
            Error::Conflict(m)    => (StatusCode::CONFLICT,             m.clone()),
            Error::Database(_)    => (StatusCode::INTERNAL_SERVER_ERROR, "database error".into()),
            Error::Internal(_)    => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
