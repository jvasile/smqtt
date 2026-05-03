use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    crypto::b64_encode,
    db,
    error::{Error, Result},
    state::AppState,
};

fn require_admin_key(headers: &HeaderMap, expected: &str) -> Result<()> {
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided == expected {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}

// ── Registration tokens ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(default = "default_expires_in")]
    expires_in: u64,
    #[serde(default = "default_max_uses")]
    max_uses: i64,
}

fn default_expires_in() -> u64 { 3600 }
fn default_max_uses()   -> i64 { 1 }

#[derive(Serialize)]
pub struct CreateTokenResponse {
    token: String,
}

pub async fn create_registration_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>> {
    require_admin_key(&headers, &state.config.admin.api_key)?;

    let mut raw = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = b64_encode(&raw);

    let hash = token_hash(&token);
    db::create_registration_token(&state.db, &hash, req.expires_in, req.max_uses).await?;

    Ok(Json(CreateTokenResponse { token }))
}

// ── User suspension ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SuspendRequest {
    reason: Option<String>,
}

pub async fn suspend_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(req): Json<SuspendRequest>,
) -> Result<StatusCode> {
    require_admin_key(&headers, &state.config.admin.api_key)?;
    db::set_suspended(&state.db, &user_id, true, req.reason.as_deref()).await?;
    crate::broker::kick_user(&state, &user_id).await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn unsuspend_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<StatusCode> {
    require_admin_key(&headers, &state.config.admin.api_key)?;
    db::set_suspended(&state.db, &user_id, false, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn token_hash(token: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(b"smqtt-token-hash")
        .expect("HMAC accepts any key length");
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
