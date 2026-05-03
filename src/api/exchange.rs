use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    api::extractors::AuthUser,
    crypto::{b64_decode, b64_encode},
    db,
    error::{Error, Result},
    state::AppState,
};

#[derive(Deserialize)]
pub struct InitiateRequest {
    peer_id:          String,
    ephemeral_pubkey: String,
}

#[derive(Serialize)]
pub struct InitiateResponse {
    exchange_id: String,
}

pub async fn initiate(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<InitiateRequest>,
) -> Result<Json<InitiateResponse>> {
    // Verify peer exists
    db::get_user(&state.db, &req.peer_id).await?;

    let pubkey = b64_decode(&req.ephemeral_pubkey)?;
    if pubkey.len() != 32 {
        return Err(Error::BadRequest("ephemeral_pubkey must be 32 bytes (X25519)".into()));
    }

    let exchange = db::create_exchange(&state.db, &user_id, &req.peer_id, &pubkey).await?;

    // Notify peer via their personal MQTT topic
    let notify_topic = state.notify_topic(&req.peer_id);
    let payload = serde_json::json!({
        "type":        "pending_exchange",
        "exchange_id": exchange.exchange_id,
    });
    crate::broker::publish_system(&state, &notify_topic, payload.to_string().into_bytes()).await;

    Ok(Json(InitiateResponse { exchange_id: exchange.exchange_id }))
}

#[derive(Serialize)]
pub struct ExchangeResponse {
    exchange_id:      String,
    initiator_id:     String,
    responder_id:     String,
    initiator_pubkey: String,
    responder_pubkey: Option<String>,
}

pub async fn get(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(exchange_id): Path<String>,
) -> Result<Json<ExchangeResponse>> {
    let ex = db::get_exchange(&state.db, &exchange_id).await?;

    // Only initiator or responder may view
    if ex.initiator_id != user_id && ex.responder_id != user_id {
        return Err(Error::Forbidden);
    }

    let complete        = ex.responder_pubkey.is_some();
    let is_initiator    = ex.initiator_id == user_id;
    let responder_pubkey = ex.responder_pubkey.map(|b| b64_encode(&b));

    // Both parties now have each other's keys — discard the record
    if complete && is_initiator {
        let _ = db::delete_exchange(&state.db, &exchange_id).await;
    }

    Ok(Json(ExchangeResponse {
        exchange_id,
        initiator_id:     ex.initiator_id,
        responder_id:     ex.responder_id,
        initiator_pubkey: b64_encode(&ex.initiator_pubkey),
        responder_pubkey,
    }))
}

#[derive(Deserialize)]
pub struct RespondRequest {
    ephemeral_pubkey: String,
}

pub async fn respond(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(exchange_id): Path<String>,
    Json(req): Json<RespondRequest>,
) -> Result<Json<ExchangeResponse>> {
    let ex = db::get_exchange(&state.db, &exchange_id).await?;

    if ex.responder_id != user_id {
        return Err(Error::Forbidden);
    }
    if ex.responder_pubkey.is_some() {
        return Err(Error::Conflict("exchange already has a response".into()));
    }

    let pubkey = b64_decode(&req.ephemeral_pubkey)?;
    if pubkey.len() != 32 {
        return Err(Error::BadRequest("ephemeral_pubkey must be 32 bytes (X25519)".into()));
    }

    db::set_responder_pubkey(&state.db, &exchange_id, &pubkey).await?;

    // Notify initiator that the exchange is complete
    let notify_topic = state.notify_topic(&ex.initiator_id);
    let payload = serde_json::json!({
        "type":        "exchange_complete",
        "exchange_id": exchange_id,
    });
    crate::broker::publish_system(&state, &notify_topic, payload.to_string().into_bytes()).await;

    Ok(Json(ExchangeResponse {
        exchange_id,
        initiator_id:     ex.initiator_id,
        responder_id:     ex.responder_id.clone(),
        initiator_pubkey: b64_encode(&ex.initiator_pubkey),
        responder_pubkey: Some(b64_encode(&pubkey)),
    }))
}
