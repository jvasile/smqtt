CREATE TABLE IF NOT EXISTS users (
    user_id        TEXT PRIMARY KEY,
    created_at     INTEGER NOT NULL,
    suspended      INTEGER NOT NULL DEFAULT 0,
    suspend_reason TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(user_id),
    pubkey        BLOB NOT NULL,
    registered_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS relationships (
    relationship_id  TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(user_id),
    peer_id          TEXT NOT NULL,
    publish_topics   TEXT NOT NULL,  -- JSON array
    subscribe_topics TEXT NOT NULL,  -- JSON array
    created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_exchanges (
    exchange_id       TEXT PRIMARY KEY,
    initiator_id      TEXT NOT NULL REFERENCES users(user_id),
    responder_id      TEXT NOT NULL,
    initiator_pubkey  BLOB NOT NULL,
    responder_pubkey  BLOB,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS registration_tokens (
    token_id   TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    max_uses   INTEGER NOT NULL DEFAULT 1,
    uses       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    code_hash  BLOB PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(user_id),
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id       ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_relationships_user_id ON relationships(user_id);
CREATE INDEX IF NOT EXISTS idx_exchanges_expires_at  ON pending_exchanges(expires_at);
