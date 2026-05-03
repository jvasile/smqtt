mod auth_hook;

use rmqtt::{
    context::ServerContext,
    hook::Type,
    net::Builder,
    server::MqttServer,
};

use crate::state::AppState;

pub use auth_hook::SmqttAuthHandler;

/// Initialise and run the embedded rmqtt broker.
/// Registers the SMQTT auth handler and starts listening on the configured address.
pub async fn run(state: AppState, bind: &str) -> anyhow::Result<()> {
    let scx = ServerContext::new().node_id(state.node_id).build().await;

    // Register auth handler
    let register = scx.extends.hook_mgr().register();
    register
        .add_priority(
            Type::ClientAuthenticate,
            10,
            Box::new(SmqttAuthHandler { state: state.clone() }),
        )
        .await;

    // Parse bind address
    let addr: std::net::SocketAddr = bind.parse()?;

    MqttServer::new(scx.clone())
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
/// Used to send notifications to connected clients.
pub async fn publish_system(state: &AppState, topic: &str, payload: Vec<u8>) {
    // We need a ServerContext to publish — store it in AppState in a future
    // refactor. For now this is a no-op placeholder that logs the intent.
    // TODO: thread ServerContext through AppState so we can call
    //   scx.extends.shared().await.forwards(from, publish).await
    tracing::debug!("publish_system: topic={topic} payload_len={}", payload.len());
}

/// Force-disconnect all sessions for a user.
/// Called on suspension or account deletion.
pub async fn kick_user(state: &AppState, user_id: &str) {
    // TODO: thread ServerContext through AppState.
    // Implementation:
    //   let shared = scx.extends.shared().await;
    //   for device in db::get_device_by_user(&state.db, user_id).await? {
    //       let id = Id::from(state.node_id as u32, ByteString::from(device.device_id));
    //       let _ = shared.entry(id).kick(false, false, true).await;
    //   }
    tracing::info!("kick_user: user_id={user_id}");
}
