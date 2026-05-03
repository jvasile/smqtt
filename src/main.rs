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
    let (cfg_path, env_path) = parse_args();

    if let Some(path) = env_path {
        dotenvy::from_path(&path)
            .map_err(|e| anyhow::anyhow!("failed to load env file {path:?}: {e}"))?;
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let config = Config::load(&cfg_path)?;

    let db    = db::connect(&config.database.path).await?;
    let keys  = JwtKeys::from_base64(&config.jwt.signing_key)?;
    let scx   = rmqtt::context::ServerContext::new().node_id(1).build().await;
    let state = AppState::new(db, config.clone(), keys, scx);

    let http_bind = config.http.bind.clone();
    let mqtt_bind = config.mqtt.bind.clone();

    // Periodically purge expired key exchanges
    let purge_db = state.db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            match db::purge_expired_exchanges(&purge_db).await {
                Ok(n) if n > 0 => tracing::info!("purged {n} expired exchanges"),
                Err(e)         => tracing::warn!("exchange purge failed: {e}"),
                _              => {}
            }
        }
    });

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

fn parse_args() -> (String, Option<String>) {
    let mut args = std::env::args().skip(1);
    let mut cfg_path = None;
    let mut env_path = None;

    while let Some(arg) = args.next() {
        if arg == "--env" {
            env_path = args.next();
        } else if let Some(val) = arg.strip_prefix("--env=") {
            env_path = Some(val.to_owned());
        } else if cfg_path.is_none() {
            cfg_path = Some(arg);
        }
    }

    (cfg_path.unwrap_or_else(|| "smqtt.toml".into()), env_path)
}
