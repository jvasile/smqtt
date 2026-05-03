use axum::{body::Body, http::{Request, StatusCode}};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::{
    api,
    config::{
        AdminConfig, Config, DatabaseConfig, HttpConfig, JwtConfig, MqttConfig,
        NotificationsConfig, RegistrationConfig, RegistrationMode, SuspensionConfig, PolicyKind,
    },
    crypto::JwtKeys,
    db,
    state::AppState,
};

// 32 zero bytes, base64url-encoded — deterministic test JWT key
const TEST_JWT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

async fn test_state() -> AppState {
    let pool = db::connect(":memory:").await.unwrap();
    let jwt_keys = JwtKeys::from_base64(TEST_JWT_KEY).unwrap();
    let scx = rmqtt::context::ServerContext::new().node_id(1).build().await;
    let config = Config {
        database:      DatabaseConfig { path: ":memory:".into() },
        http:          HttpConfig     { bind: "127.0.0.1:0".into() },
        mqtt:          MqttConfig     { bind: "127.0.0.1:0".into() },
        registration:  RegistrationConfig { mode: RegistrationMode::Open, policy: None },
        suspension:    SuspensionConfig   { kind: PolicyKind::Push, hook_url: None },
        admin:         AdminConfig        { api_key: "test-admin-key".into() },
        notifications: NotificationsConfig { notify_secret: "test-notify-secret".into() },
        jwt:           JwtConfig { signing_key: TEST_JWT_KEY.into(), ttl_seconds: 3600 },
    };
    AppState::new(pool, config, jwt_keys, scx)
}

fn json_req(method: &str, uri: &str, body: Value, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token { b = b.header("authorization", format!("Bearer {t}")); }
    b.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

fn get_req(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(t) = token { b = b.header("authorization", format!("Bearer {t}")); }
    b.body(Body::empty()).unwrap()
}

fn delete_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Register a user, go through challenge-response, return (user_id, device_id, jwt).
async fn register_and_auth(app: &axum::Router) -> (String, String, String) {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let pubkey_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());

    // Register
    let resp = app.clone()
        .oneshot(json_req("POST", "/register", json!({ "pubkey": pubkey_b64 }), None))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register failed");
    let reg = json_body(resp).await;
    let user_id   = reg["user_id"].as_str().unwrap().to_owned();
    let device_id = reg["device_id"].as_str().unwrap().to_owned();

    // Challenge
    let resp = app.clone()
        .oneshot(get_req(&format!("/auth/challenge?user_id={user_id}"), None))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "challenge failed");
    let nonce = URL_SAFE_NO_PAD
        .decode(json_body(resp).await["nonce"].as_str().unwrap())
        .unwrap();

    // Verify
    let sig_b64 = URL_SAFE_NO_PAD.encode(signing_key.sign(&nonce).to_bytes());
    let resp = app.clone()
        .oneshot(json_req("POST", "/auth/verify", json!({
            "user_id":   user_id,
            "device_id": device_id,
            "signature": sig_b64,
        }), None))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "verify failed");
    let token = json_body(resp).await["token"].as_str().unwrap().to_owned();

    (user_id, device_id, token)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_register_and_auth() {
    let state = test_state().await;
    let app   = api::router(state.clone());

    let (user_id, _device_id, token) = register_and_auth(&app).await;

    let claims = state.jwt_keys.verify(&token).unwrap();
    assert_eq!(claims.sub, user_id);
    // Notify topic is always appended to sub_topics at auth time
    assert!(claims.sub_topics.contains(&claims.notify_topic));
}

#[tokio::test]
async fn test_key_exchange() {
    let state = test_state().await;
    let app   = api::router(state.clone());

    let (alice_id, _, alice_token) = register_and_auth(&app).await;
    let (bob_id,   _, bob_token)   = register_and_auth(&app).await;

    let alice_pubkey_b64 = URL_SAFE_NO_PAD.encode([1u8; 32]);

    // Alice initiates
    let resp = app.clone()
        .oneshot(json_req("POST", "/exchange", json!({
            "peer_id":         bob_id,
            "ephemeral_pubkey": alice_pubkey_b64,
        }), Some(&alice_token)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let exchange_id = json_body(resp).await["exchange_id"].as_str().unwrap().to_owned();

    // Bob fetches — sees Alice's pubkey, no responder key yet
    let resp = app.clone()
        .oneshot(get_req(&format!("/exchange/{exchange_id}"), Some(&bob_token)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["initiator_id"].as_str().unwrap(), alice_id);
    assert_eq!(body["initiator_pubkey"].as_str().unwrap(), alice_pubkey_b64);
    assert!(body["responder_pubkey"].is_null());

    // Bob responds
    let bob_pubkey_b64 = URL_SAFE_NO_PAD.encode([2u8; 32]);
    let resp = app.clone()
        .oneshot(json_req("POST", &format!("/exchange/{exchange_id}/respond"), json!({
            "ephemeral_pubkey": bob_pubkey_b64,
        }), Some(&bob_token)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Alice fetches completed exchange — both pubkeys present
    let resp = app.clone()
        .oneshot(get_req(&format!("/exchange/{exchange_id}"), Some(&alice_token)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["initiator_pubkey"].as_str().unwrap(), alice_pubkey_b64);
    assert_eq!(body["responder_pubkey"].as_str().unwrap(), bob_pubkey_b64);

    // Third party (neither alice nor bob) cannot fetch the exchange
    let (_, _, eve_token) = register_and_auth(&app).await;
    let resp = app.clone()
        .oneshot(get_req(&format!("/exchange/{exchange_id}"), Some(&eve_token)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_relationship_revocation() {
    let state = test_state().await;
    let app   = api::router(state.clone());

    let (alice_id, _, alice_token) = register_and_auth(&app).await;
    let (bob_id,   _, _bob_token)  = register_and_auth(&app).await;

    // Create relationship
    let resp = app.clone()
        .oneshot(json_req("POST", "/relationships", json!({
            "peer_id":          bob_id,
            "publish_topics":   ["topic-a-to-b"],
            "subscribe_topics": ["topic-b-to-a"],
        }), Some(&alice_token)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rel_id = json_body(resp).await["relationship_id"].as_str().unwrap().to_owned();

    // List — relationship present
    let resp = app.clone()
        .oneshot(get_req("/relationships", Some(&alice_token)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rels = json_body(resp).await;
    assert_eq!(rels.as_array().unwrap().len(), 1);
    assert_eq!(rels[0]["relationship_id"].as_str().unwrap(), rel_id);

    // Revoke
    let resp = app.clone()
        .oneshot(delete_req(&format!("/relationships/{rel_id}"), &alice_token))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List — empty
    let resp = app.clone()
        .oneshot(get_req("/relationships", Some(&alice_token)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(json_body(resp).await.as_array().unwrap().is_empty());

    // DB confirms gone
    assert!(db::list_relationships(&state.db, &alice_id).await.unwrap().is_empty());
    // Direct fetch by relationship_id also returns NotFound
    assert!(db::get_relationship(&state.db, &alice_id, &rel_id).await.is_err());
}
