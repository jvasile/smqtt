mod api;
mod broker;
#[cfg(test)] mod tests;
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
        if arg == "--help" || arg == "-h" {
            print_help();
            std::process::exit(0);
        } else if arg == "--env" {
            env_path = args.next();
        } else if let Some(val) = arg.strip_prefix("--env=") {
            env_path = Some(val.to_owned());
        } else if cfg_path.is_none() {
            cfg_path = Some(arg);
        }
    }

    let cfg_path = cfg_path
        .or_else(|| std::env::var("SMQTT_CONFIG").ok())
        .unwrap_or_else(|| "smqtt.toml".into());

    (cfg_path, env_path)
}

fn print_help() {
    println!("\
Usage: smqtt [OPTIONS] [CONFIG]

Arguments:
  [CONFIG]   Path to the TOML config file  [default: smqtt.toml]
             Also set via SMQTT_CONFIG env var; CLI arg takes precedence.

Options:
  --env <FILE>   Load environment variables from FILE before startup
  -h, --help     Print this message and exit

Config env vars (override values in the TOML file):
  SMQTT__DATABASE__PATH
  SMQTT__HTTP__BIND
  SMQTT__MQTT__BIND
  SMQTT__REGISTRATION__MODE
  SMQTT__ADMIN__API_KEY
  SMQTT__NOTIFICATIONS__NOTIFY_SECRET
  SMQTT__JWT__SIGNING_KEY
  SMQTT__JWT__TTL_SECONDS");
}
