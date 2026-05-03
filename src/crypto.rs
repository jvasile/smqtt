use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

// ── JWT ──────────────────────────────────────────────────────────────────────

/// Claims encoded in every JWT issued to a device.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub:          String,          // user_id
    pub dev:          String,          // device_id
    pub exp:          u64,
    pub iat:          u64,
    pub pub_topics:   Vec<String>,     // topics the device may publish to
    pub sub_topics:   Vec<String>,     // topics the device may subscribe to
    pub notify_topic: String,          // personal notification topic
}

pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKeys {
    pub fn from_base64(b64: &str) -> anyhow::Result<Self> {
        let raw = URL_SAFE_NO_PAD.decode(b64)?;
        // Ed25519 keys are 32 bytes (private) + 32 bytes (public) = 64 bytes
        // For HMAC-based JWT signing in this implementation we use HS256
        // with the raw key bytes. Switch to ES256/EdDSA when jsonwebtoken
        // adds stable Ed25519 support.
        Ok(Self {
            encoding: EncodingKey::from_secret(&raw),
            decoding: DecodingKey::from_secret(&raw),
        })
    }

    pub fn issue(
        &self,
        user_id: &str,
        device_id: &str,
        ttl_seconds: u64,
        pub_topics: Vec<String>,
        sub_topics: Vec<String>,
        notify_topic: String,
    ) -> Result<String> {
        let now = unix_now();
        let claims = Claims {
            sub: user_id.to_owned(),
            dev: device_id.to_owned(),
            exp: now + ttl_seconds,
            iat: now,
            pub_topics,
            sub_topics,
            notify_topic,
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|e| Error::Internal(e.into()))
    }

    pub fn verify(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        decode::<Claims>(token, &self.decoding, &validation)
            .map(|d| d.claims)
            .map_err(|_| Error::Unauthorized)
    }
}

// ── Notification topic derivation ────────────────────────────────────────────

/// Derive the personal notification topic for a user.
/// Uses HMAC-SHA256(notify_secret, "notify:{user_id}").
/// Only SMQTT can derive this — the secret lives in config.
pub fn notification_topic(notify_secret: &[u8], user_id: &str) -> String {
    let msg = format!("notify:{user_id}");
    let mut mac = Hmac::<Sha256>::new_from_slice(notify_secret)
        .expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| Error::BadRequest(format!("invalid base64: {e}")))
}
