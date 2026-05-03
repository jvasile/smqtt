use axum::{extract::State, Json};
use ed25519_dalek::VerifyingKey;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    config::{PolicyKind, RegistrationMode},
    crypto::b64_decode,
    db,
    error::{Error, Result},
    state::AppState,
};

#[derive(Deserialize)]
pub struct RegisterRequest {
    /// Ed25519 public key, base64url-encoded raw bytes (32 bytes).
    pubkey: String,
    /// Required when registration mode is policy/push.
    registration_token: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    user_id:   String,
    device_id: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    // 1. Validate registration policy
    match state.config.registration.mode {
        RegistrationMode::Closed => return Err(Error::Forbidden),

        RegistrationMode::Policy => {
            let policy = state.config.registration.policy.as_ref()
                .ok_or_else(|| Error::Internal(anyhow::anyhow!("policy mode configured but no policy")))?;

            match policy.kind {
                PolicyKind::Push => {
                    let token = req.registration_token.as_deref()
                        .ok_or(Error::BadRequest("registration_token required".into()))?;
                    let hash = token_hash(token);
                    db::consume_registration_token(&state.db, &hash).await?;
                }
                PolicyKind::Hook => {
                    let url = policy.hook_url.as_deref()
                        .ok_or_else(|| Error::Internal(anyhow::anyhow!("hook_url not configured")))?;
                    validate_via_hook(url, &req.pubkey).await?;
                }
            }
        }

        RegistrationMode::Open => {}
    }

    // 2. Decode and validate the public key
    let pubkey_bytes = b64_decode(&req.pubkey)?;
    if pubkey_bytes.len() != 32 {
        return Err(Error::BadRequest("pubkey must be 32 bytes (Ed25519)".into()));
    }
    let key_array: [u8; 32] = pubkey_bytes.try_into().unwrap();
    VerifyingKey::from_bytes(&key_array)
        .map_err(|_| Error::BadRequest("invalid Ed25519 public key".into()))?;

    // 3. Create user and device records
    let user   = db::create_user(&state.db).await?;
    let device = db::create_device(&state.db, &user.user_id, &key_array).await?;

    Ok(Json(RegisterResponse {
        user_id:   user.user_id,
        device_id: device.device_id,
    }))
}

fn token_hash(token: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(b"smqtt-token-hash")
        .expect("HMAC accepts any key length");
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

async fn validate_via_hook(url: &str, pubkey: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .json(&serde_json::json!({ "pubkey": pubkey }))
        .send()
        .await
        .map_err(|e| Error::Internal(e.into()))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| Error::Internal(e.into()))?;
    if body.get("allowed").and_then(|v| v.as_bool()).unwrap_or(false) {
        Ok(())
    } else {
        Err(Error::Forbidden)
    }
}
