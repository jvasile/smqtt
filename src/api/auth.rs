use axum::{extract::{Query, State}, Json};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{b64_decode, b64_encode, unix_now},
    db,
    error::{Error, Result},
    state::AppState,
};

const CHALLENGE_TTL_SECS: u64 = 60;

// ── Challenge ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ChallengeQuery {
    user_id: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    nonce: String,
}

pub async fn challenge(
    State(state): State<AppState>,
    Query(q): Query<ChallengeQuery>,
) -> Result<Json<ChallengeResponse>> {
    // Verify user exists before issuing challenge
    db::get_user(&state.db, &q.user_id).await?;

    let mut nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let expires_at = unix_now() + CHALLENGE_TTL_SECS;
    state.challenges.insert(q.user_id.clone(), (nonce.clone(), expires_at));

    Ok(Json(ChallengeResponse { nonce: b64_encode(&nonce) }))
}

// ── Verify ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyRequest {
    user_id:   String,
    device_id: String,
    signature: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    token: String,
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>> {
    // 1. Pop and validate challenge
    let (nonce, expires_at) = state
        .challenges
        .remove(&req.user_id)
        .map(|(_, v)| v)
        .ok_or(Error::Unauthorized)?;

    if unix_now() > expires_at {
        return Err(Error::Unauthorized);
    }

    // 2. Check user is not suspended
    let user = db::get_user(&state.db, &req.user_id).await?;
    if user.suspended {
        return Err(Error::Forbidden);
    }

    // 3. Find the device and verify signature
    let devices = db::get_device_by_user(&state.db, &req.user_id).await?;
    let device = devices
        .iter()
        .find(|d| d.device_id == req.device_id)
        .ok_or(Error::Unauthorized)?;

    let key_array: [u8; 32] = device.pubkey.clone().try_into()
        .map_err(|_| Error::Internal(anyhow::anyhow!("invalid pubkey in db")))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| Error::Internal(anyhow::anyhow!("invalid pubkey in db")))?;

    let sig_bytes = b64_decode(&req.signature)?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| Error::BadRequest("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(&nonce, &signature)
        .map_err(|_| Error::Unauthorized)?;

    // 4. Gather topic permissions and issue JWT
    let (pub_topics, mut sub_topics) = db::user_topics(&state.db, &req.user_id).await?;
    let notify_topic = state.notify_topic(&req.user_id);
    sub_topics.push(notify_topic.clone());

    let token = state.jwt_keys.issue(
        &req.user_id,
        &req.device_id,
        state.config.jwt.ttl_seconds,
        pub_topics,
        sub_topics,
        notify_topic,
    )?;

    Ok(Json(VerifyResponse { token }))
}
