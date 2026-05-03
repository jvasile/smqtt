mod auth_hook;

use bytes::Bytes;
use bytestring::ByteString;
use rmqtt::{
    hook::Type,
    net::Builder,
    server::MqttServer,
    types::{CodecPublish, From, Id, Publish, QoS},
};

use crate::state::AppState;

pub use auth_hook::SmqttAuthHandler;

/// Initialise and run the embedded rmqtt broker.
pub async fn run(state: AppState, bind: &str) -> anyhow::Result<()> {
    let scx = state.scx.clone();

    let register = scx.extends.hook_mgr().register();
    let handler = Box::new(SmqttAuthHandler { state: state.clone() });
    register.add_priority(Type::ClientAuthenticate,      10, handler.clone()).await;
    register.add_priority(Type::ClientSubscribeCheckAcl, 10, handler.clone()).await;
    register.add_priority(Type::ClientDisconnected,      10, handler).await;

    let addr: std::net::SocketAddr = bind.parse()?;

    MqttServer::new(scx)
        .listener(
            Builder::new()
                .name("external/tcp")
                .laddr(addr)
                .allow_anonymous(false)
                .bind()?
                .tcp()?,
        )
        .build()
        .run()
        .await?;

    Ok(())
}

/// Publish a message into the broker from the system (no client session).
pub async fn publish_system(state: &AppState, topic: &str, payload: Vec<u8>) {
    let shared = state.scx.extends.shared().await;
    let id = Id::from(state.node_id, ByteString::from("smqtt-system"));
    let from = From::from_system(id);
    let codec_pub = CodecPublish {
        dup:        false,
        retain:     false,
        qos:        QoS::AtLeastOnce,
        topic:      ByteString::from(topic),
        packet_id:  None,
        payload:    Bytes::from(payload),
        properties: None,
    };
    let publish = Publish::new(Box::new(codec_pub), None, None, None);
    if let Err(errors) = shared.forwards(from, publish).await {
        tracing::warn!("publish_system: {} delivery errors on topic={topic}", errors.len());
    }
}

/// Force-disconnect all sessions for a user.
/// Called on suspension or relationship revocation so the client re-auths
/// and gets a JWT reflecting the updated topic list.
pub async fn kick_user(state: &AppState, user_id: &str) {
    let shared = state.scx.extends.shared().await;
    let devices = match crate::db::get_device_by_user(&state.db, user_id).await {
        Ok(d)  => d,
        Err(e) => { tracing::warn!("kick_user: db error for {user_id}: {e}"); return; }
    };
    for device in devices {
        let id = Id::from(state.node_id, ByteString::from(device.device_id));
        let _ = shared.entry(id).kick(false, false, true).await;
    }
}
