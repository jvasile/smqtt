use std::sync::Arc;
use dashmap::DashMap;
use sqlx::SqlitePool;

use crate::config::Config;
use crate::crypto::JwtKeys;

/// In-memory challenge store: user_id -> (nonce_bytes, expires_at_unix_secs)
pub type Challenges = Arc<DashMap<String, (Vec<u8>, u64)>>;

/// Shared application state passed to all Axum handlers and the broker auth hook.
#[derive(Clone)]
pub struct AppState {
    pub db:         SqlitePool,
    pub config:     Arc<Config>,
    pub jwt_keys:   Arc<JwtKeys>,
    pub challenges: Challenges,
    /// SMQTT node id — used when publishing system messages into rmqtt.
    pub node_id:    u64,
}

impl AppState {
    pub fn new(db: SqlitePool, config: Config, jwt_keys: JwtKeys) -> Self {
        Self {
            db,
            config:     Arc::new(config),
            jwt_keys:   Arc::new(jwt_keys),
            challenges: Arc::new(DashMap::new()),
            node_id:    1,
        }
    }

    /// Derive the notification topic for a user.
    pub fn notify_topic(&self, user_id: &str) -> String {
        let secret = self.config.notifications.notify_secret.as_bytes();
        crate::crypto::notification_topic(secret, user_id)
    }
}
