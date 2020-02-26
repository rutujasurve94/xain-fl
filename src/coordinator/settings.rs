use config::{Config, ConfigError};

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub log_level: String,
    pub aggregator_url: String,
    pub api: ApiSettings,
    pub rpc: RpcSettings,
    pub federated_learning: FederatedLearningSettings,
}

#[derive(Debug, Deserialize)]
pub struct FederatedLearningSettings {
    pub rounds: u32,
    pub participants_ratio: f64,
    pub min_clients: u32,
    pub heartbeat_timeout: u64,
    // epoch: u32,
}

#[derive(Debug, Deserialize)]
pub struct ApiSettings {
    pub bind_address: String,
}

#[derive(Debug, Deserialize)]
pub struct RpcSettings {
    pub bind_address: String,
    pub aggregator_address: String,
}

impl Settings {
    pub fn new(path: &str) -> Result<Self, ConfigError> {
        let mut s = Config::new();
        s.merge(config::File::with_name(path))?;
        s.try_into()
    }
}
