use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database:      DatabaseConfig,
    pub http:          HttpConfig,
    pub mqtt:          MqttConfig,
    pub registration:  RegistrationConfig,
    pub suspension:    SuspensionConfig,
    pub admin:         AdminConfig,
    pub notifications: NotificationsConfig,
    pub jwt:           JwtConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// SQLite database path. Use ":memory:" for tests.
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MqttConfig {
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// Ed25519 private key for signing JWTs, base64-encoded raw bytes.
    /// Generated on first run if not set.
    pub signing_key: String,
    /// Token lifetime in seconds.
    #[serde(default = "default_jwt_ttl")]
    pub ttl_seconds: u64,
}

fn default_jwt_ttl() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationConfig {
    pub mode: RegistrationMode,
    pub policy: Option<RegistrationPolicy>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationMode {
    Open,
    Closed,
    Policy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationPolicy {
    #[serde(rename = "type")]
    pub kind: PolicyKind,
    pub hook_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyKind {
    Push,
    Hook,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SuspensionConfig {
    #[serde(rename = "type")]
    pub kind: PolicyKind,
    pub hook_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub api_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotificationsConfig {
    /// Secret used to derive per-user notification topics.
    /// Generated on first run if not set.
    pub notify_secret: String,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name(path))
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}
