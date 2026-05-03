use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    api::extractors::AuthUser,
    db,
    error::Result,
    state::AppState,
};

#[derive(Deserialize)]
pub struct CreateRequest {
    peer_id:          String,
    publish_topics:   Vec<String>,
    subscribe_topics: Vec<String>,
}

#[derive(Serialize)]
pub struct RelationshipResponse {
    relationship_id:  String,
    user_id:          String,
    peer_id:          String,
    publish_topics:   Vec<String>,
    subscribe_topics: Vec<String>,
    created_at:       i64,
}

pub async fn create(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<CreateRequest>,
) -> Result<Json<RelationshipResponse>> {
    let rel = db::create_relationship(
        &state.db,
        &user_id,
        &req.peer_id,
        &req.publish_topics,
        &req.subscribe_topics,
    )
    .await?;

    Ok(Json(RelationshipResponse {
        relationship_id:  rel.relationship_id,
        user_id:          rel.user_id,
        peer_id:          rel.peer_id,
        publish_topics:   req.publish_topics,
        subscribe_topics: req.subscribe_topics,
        created_at:       rel.created_at,
    }))
}

pub async fn list(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<RelationshipResponse>>> {
    let rels = db::list_relationships(&state.db, &user_id).await?;
    let resp = rels
        .into_iter()
        .map(|r| RelationshipResponse {
            relationship_id:  r.relationship_id,
            user_id:          r.user_id,
            peer_id:          r.peer_id,
            publish_topics:   serde_json::from_str(&r.publish_topics).unwrap_or_default(),
            subscribe_topics: serde_json::from_str(&r.subscribe_topics).unwrap_or_default(),
            created_at:       r.created_at,
        })
        .collect();
    Ok(Json(resp))
}

pub async fn revoke(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(relationship_id): Path<String>,
) -> Result<()> {
    let rel = db::get_relationship(&state.db, &user_id, &relationship_id).await?;
    db::delete_relationship(&state.db, &user_id, &relationship_id).await?;
    crate::broker::kick_user(&state, &user_id).await;
    crate::broker::kick_user(&state, &rel.peer_id).await;
    Ok(())
}
