mod api;
mod broker;
mod config;
mod crypto;
mod db;
mod error;
mod state;

use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

use crate::{
    config::Config,
    crypto::JwtKeys,
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| "smqtt.toml".into());
    let config = Config::load(&cfg_path)?;

    let db    = db::connect(&config.database.path).await?;
    let keys  = JwtKeys::from_base64(&config.jwt.signing_key)?;
    let scx   = rmqtt::context::ServerContext::new().node_id(1).build().await;
    let state = AppState::new(db, config.clone(), keys, scx);

    let http_bind = config.http.bind.clone();
    let mqtt_bind = config.mqtt.bind.clone();

    // Spawn broker in background task
    let broker_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = broker::run(broker_state, &mqtt_bind).await {
            tracing::error!("broker error: {e}");
        }
    });

    // Run HTTP API
    let router   = api::router(state);
    let addr: SocketAddr = http_bind.parse()?;
    tracing::info!("HTTP API listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
