#![allow(dead_code)]

use std::net::SocketAddr;

use serde::Deserialize;

/// Top-level application configuration, loaded from config.yaml.
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub dns: DnsConfig,
    pub blocklist: BlocklistConfig,
    pub database: DatabaseConfig,
    pub analyzer: AnalyzerConfig,
    pub reporter: ReporterConfig,
}

/// DNS server settings.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    pub listen_addr: String,
    pub upstream_servers: Vec<String>,
    pub timeout_ms: u64,
    /// If set, only these clients are filtered. All other clients pass through unfiltered.
    /// If empty, all clients are filtered.
    #[serde(default)]
    pub filtered_clients: Vec<FilteredClient>,
}

/// A client device to filter, identified by name and IP/MAC address.
#[derive(Debug, Clone, Deserialize)]
pub struct FilteredClient {
    pub name: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
}

/// Blocklist configuration including public sources and custom overrides.
#[derive(Debug, Deserialize)]
pub struct BlocklistConfig {
    pub sources: Vec<BlocklistSource>,
    pub custom_block: Vec<String>,
    pub custom_allow: Vec<String>,
    pub sync_interval_hours: u64,
    pub cache_dir: String,
}

/// A single public blocklist source.
#[derive(Debug, Deserialize)]
pub struct BlocklistSource {
    pub name: String,
    pub url: String,
    pub category: String,
}

/// Database settings.
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

/// Analyzer (OpenAI) settings.
#[derive(Debug, Deserialize)]
pub struct AnalyzerConfig {
    pub schedule: String,
    pub lookback_days: i64,
    pub report_top_domains: usize,
}

/// Email reporter settings.
#[derive(Debug, Deserialize)]
pub struct ReporterConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub from_email: String,
    pub to_emails: Vec<String>,
}

impl DnsConfig {
    /// Parse upstream server strings into socket addresses.
    pub fn upstream_addrs(&self) -> anyhow::Result<Vec<SocketAddr>> {
        self.upstream_servers
            .iter()
            .map(|s| s.parse::<SocketAddr>().map_err(Into::into))
            .collect()
    }
}

/// Load configuration from config.yaml and .env.
pub fn load() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();

    let settings = config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()?;

    let app_config: AppConfig = settings.try_deserialize()?;
    Ok(app_config)
}
