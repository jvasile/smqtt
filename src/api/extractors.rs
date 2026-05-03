use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
};

use crate::{error::Error, state::AppState};

/// Extracts and validates the JWT from the Authorization header,
/// returning the user_id claim.
pub struct AuthUser(pub String);

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !auth.starts_with("Bearer ") {
            return Err(Error::Unauthorized);
        }

        let token = &auth[7..];
        let claims = state.jwt_keys.verify(token)?;
        Ok(AuthUser(claims.sub))
    }
}
