use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use uuid::Uuid;

use crate::crypto::unix_now;
use crate::error::{Error, Result};

pub async fn connect(path: &str) -> anyhow::Result<SqlitePool> {
    let url = if path == ":memory:" {
        "sqlite::memory:".to_owned()
    } else {
        format!("sqlite:{path}?mode=rwc")
    };

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await?;

    sqlx::migrate!("src/db/migrations").run(&pool).await?;

    Ok(pool)
}

// ── Users ─────────────────────────────────────────────────────────────────────

pub struct User {
    pub user_id:        String,
    pub created_at:     i64,
    pub suspended:      bool,
    pub suspend_reason: Option<String>,
}

pub async fn create_user(pool: &SqlitePool) -> Result<User> {
    let user_id = Uuid::new_v4().to_string();
    let now = unix_now() as i64;
    sqlx::query!(
        "INSERT INTO users (user_id, created_at, suspended) VALUES (?, ?, 0)",
        user_id, now
    )
    .execute(pool)
    .await?;
    Ok(User { user_id, created_at: now, suspended: false, suspend_reason: None })
}

pub async fn get_user(pool: &SqlitePool, user_id: &str) -> Result<User> {
    sqlx::query_as!(
        User,
        "SELECT user_id as \"user_id!\", created_at as \"created_at!\",
                suspended as \"suspended: bool\", suspend_reason
         FROM users WHERE user_id = ?",
        user_id
    )
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)
}

pub async fn set_suspended(
    pool: &SqlitePool,
    user_id: &str,
    suspended: bool,
    reason: Option<&str>,
) -> Result<()> {
    let rows = sqlx::query!(
        "UPDATE users SET suspended = ?, suspend_reason = ? WHERE user_id = ?",
        suspended, reason, user_id
    )
    .execute(pool)
    .await?
    .rows_affected();
    if rows == 0 { Err(Error::NotFound) } else { Ok(()) }
}

// ── Devices ───────────────────────────────────────────────────────────────────

pub struct Device {
    pub device_id:     String,
    pub user_id:       String,
    pub pubkey:        Vec<u8>,
    pub registered_at: i64,
}

pub async fn create_device(
    pool: &SqlitePool,
    user_id: &str,
    pubkey: &[u8],
) -> Result<Device> {
    let device_id = Uuid::new_v4().to_string();
    let now = unix_now() as i64;
    sqlx::query!(
        "INSERT INTO devices (device_id, user_id, pubkey, registered_at) VALUES (?, ?, ?, ?)",
        device_id, user_id, pubkey, now
    )
    .execute(pool)
    .await?;
    Ok(Device { device_id, user_id: user_id.to_owned(), pubkey: pubkey.to_vec(), registered_at: now })
}

pub async fn get_device_by_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<Device>> {
    Ok(sqlx::query_as!(
        Device,
        "SELECT device_id as \"device_id!\", user_id as \"user_id!\",
                pubkey as \"pubkey!\", registered_at as \"registered_at!\"
         FROM devices WHERE user_id = ?",
        user_id
    )
    .fetch_all(pool)
    .await?)
}

// ── Relationships ─────────────────────────────────────────────────────────────

pub struct Relationship {
    pub relationship_id:  String,
    pub user_id:          String,
    pub peer_id:          String,
    pub publish_topics:   String,  // JSON array
    pub subscribe_topics: String,  // JSON array
    pub created_at:       i64,
}

pub async fn create_relationship(
    pool: &SqlitePool,
    user_id: &str,
    peer_id: &str,
    publish_topics: &[String],
    subscribe_topics: &[String],
) -> Result<Relationship> {
    let relationship_id = Uuid::new_v4().to_string();
    let now = unix_now() as i64;
    let pub_json = serde_json::to_string(publish_topics).unwrap();
    let sub_json = serde_json::to_string(subscribe_topics).unwrap();
    sqlx::query!(
        "INSERT INTO relationships
         (relationship_id, user_id, peer_id, publish_topics, subscribe_topics, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        relationship_id, user_id, peer_id, pub_json, sub_json, now
    )
    .execute(pool)
    .await?;
    Ok(Relationship {
        relationship_id,
        user_id: user_id.to_owned(),
        peer_id: peer_id.to_owned(),
        publish_topics: pub_json,
        subscribe_topics: sub_json,
        created_at: now,
    })
}

pub async fn list_relationships(pool: &SqlitePool, user_id: &str) -> Result<Vec<Relationship>> {
    Ok(sqlx::query_as!(
        Relationship,
        "SELECT relationship_id as \"relationship_id!\", user_id as \"user_id!\",
                peer_id as \"peer_id!\", publish_topics as \"publish_topics!\",
                subscribe_topics as \"subscribe_topics!\", created_at as \"created_at!\"
         FROM relationships WHERE user_id = ?",
        user_id
    )
    .fetch_all(pool)
    .await?)
}

pub async fn get_relationship(
    pool: &SqlitePool,
    user_id: &str,
    relationship_id: &str,
) -> Result<Relationship> {
    sqlx::query_as!(
        Relationship,
        "SELECT relationship_id as \"relationship_id!\", user_id as \"user_id!\",
                peer_id as \"peer_id!\", publish_topics as \"publish_topics!\",
                subscribe_topics as \"subscribe_topics!\", created_at as \"created_at!\"
         FROM relationships WHERE relationship_id = ? AND user_id = ?",
        relationship_id, user_id
    )
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)
}

pub async fn delete_relationship(
    pool: &SqlitePool,
    user_id: &str,
    relationship_id: &str,
) -> Result<()> {
    let rows = sqlx::query!(
        "DELETE FROM relationships WHERE relationship_id = ? AND user_id = ?",
        relationship_id, user_id
    )
    .execute(pool)
    .await?
    .rows_affected();
    if rows == 0 { Err(Error::NotFound) } else { Ok(()) }
}

/// Aggregate all publish/subscribe topics for a user across all Relationships.
pub async fn user_topics(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let rels = list_relationships(pool, user_id).await?;
    let mut pub_topics = Vec::new();
    let mut sub_topics = Vec::new();
    for rel in rels {
        let p: Vec<String> = serde_json::from_str(&rel.publish_topics).unwrap_or_default();
        let s: Vec<String> = serde_json::from_str(&rel.subscribe_topics).unwrap_or_default();
        pub_topics.extend(p);
        sub_topics.extend(s);
    }
    Ok((pub_topics, sub_topics))
}

// ── Pending exchanges ─────────────────────────────────────────────────────────

pub struct PendingExchange {
    pub exchange_id:      String,
    pub initiator_id:     String,
    pub responder_id:     String,
    pub initiator_pubkey: Vec<u8>,
    pub responder_pubkey: Option<Vec<u8>>,
    pub created_at:       i64,
    pub expires_at:       i64,
}

const EXCHANGE_TTL_SECS: u64 = 7 * 24 * 3600; // 1 week

pub async fn create_exchange(
    pool: &SqlitePool,
    initiator_id: &str,
    responder_id: &str,
    initiator_pubkey: &[u8],
) -> Result<PendingExchange> {
    let exchange_id = Uuid::new_v4().to_string();
    let now = unix_now() as i64;
    let expires_at = (unix_now() + EXCHANGE_TTL_SECS) as i64;
    sqlx::query!(
        "INSERT INTO pending_exchanges
         (exchange_id, initiator_id, responder_id, initiator_pubkey, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        exchange_id, initiator_id, responder_id, initiator_pubkey, now, expires_at
    )
    .execute(pool)
    .await?;
    Ok(PendingExchange {
        exchange_id,
        initiator_id: initiator_id.to_owned(),
        responder_id: responder_id.to_owned(),
        initiator_pubkey: initiator_pubkey.to_vec(),
        responder_pubkey: None,
        created_at: now,
        expires_at,
    })
}

pub async fn get_exchange(pool: &SqlitePool, exchange_id: &str) -> Result<PendingExchange> {
    sqlx::query_as!(
        PendingExchange,
        "SELECT exchange_id as \"exchange_id!\", initiator_id as \"initiator_id!\",
                responder_id as \"responder_id!\", initiator_pubkey as \"initiator_pubkey!\",
                responder_pubkey, created_at as \"created_at!\", expires_at as \"expires_at!\"
         FROM pending_exchanges WHERE exchange_id = ?",
        exchange_id
    )
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)
}

pub async fn set_responder_pubkey(
    pool: &SqlitePool,
    exchange_id: &str,
    responder_pubkey: &[u8],
) -> Result<()> {
    let rows = sqlx::query!(
        "UPDATE pending_exchanges SET responder_pubkey = ? WHERE exchange_id = ?",
        responder_pubkey, exchange_id
    )
    .execute(pool)
    .await?
    .rows_affected();
    if rows == 0 { Err(Error::NotFound) } else { Ok(()) }
}

pub async fn delete_exchange(pool: &SqlitePool, exchange_id: &str) -> Result<()> {
    sqlx::query!("DELETE FROM pending_exchanges WHERE exchange_id = ?", exchange_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Purge expired exchanges. Call periodically.
pub async fn purge_expired_exchanges(pool: &SqlitePool) -> Result<u64> {
    let now = unix_now() as i64;
    Ok(sqlx::query!("DELETE FROM pending_exchanges WHERE expires_at < ?", now)
        .execute(pool)
        .await?
        .rows_affected())
}

// ── Registration tokens ───────────────────────────────────────────────────────

pub async fn create_registration_token(
    pool: &SqlitePool,
    token_hash: &[u8],
    expires_in_secs: u64,
    max_uses: i64,
) -> Result<String> {
    let token_id = Uuid::new_v4().to_string();
    let now = unix_now() as i64;
    let expires_at = (unix_now() + expires_in_secs) as i64;
    sqlx::query!(
        "INSERT INTO registration_tokens (token_id, token_hash, created_at, expires_at, max_uses, uses)
         VALUES (?, ?, ?, ?, ?, 0)",
        token_id, token_hash, now, expires_at, max_uses
    )
    .execute(pool)
    .await?;
    Ok(token_id)
}

/// Validate and consume a registration token. Returns Ok(()) if valid.
pub async fn consume_registration_token(pool: &SqlitePool, token_hash: &[u8]) -> Result<()> {
    let now = unix_now() as i64;
    let rows = sqlx::query!(
        "UPDATE registration_tokens
         SET uses = uses + 1
         WHERE token_hash = ? AND expires_at > ? AND uses < max_uses",
        token_hash, now
    )
    .execute(pool)
    .await?
    .rows_affected();
    if rows == 0 { Err(Error::Forbidden) } else { Ok(()) }
}
