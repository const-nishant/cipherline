//! Relay server configuration.
//!
//! Configurable via CLI args and environment variables (via `clap`).

use clap::Parser;
use std::net::SocketAddr;

/// CipherLine blind relay server.
#[derive(Parser, Debug, Clone)]
#[command(name = "cipherline-relay", version, about)]
pub struct RelayConfig {
    /// Address to bind the server to.
    #[arg(long, env = "CIPHERLINE_BIND_ADDR", default_value = "0.0.0.0:8080")]
    pub bind_addr: SocketAddr,

    /// Time-to-live for undelivered messages, in seconds.
    /// Messages older than this are purged.
    #[arg(long, env = "CIPHERLINE_MESSAGE_TTL", default_value_t = 604_800)]
    pub message_ttl_secs: u64,

    /// Maximum envelope size in bytes.
    #[arg(long, env = "CIPHERLINE_MAX_MSG_SIZE", default_value_t = 65_536)]
    pub max_message_size: usize,

    /// Maximum concurrent WebSocket connections.
    #[arg(long, env = "CIPHERLINE_MAX_CONNECTIONS", default_value_t = 10_000)]
    pub max_connections: usize,

    /// Per-IP rate limit: maximum messages per second.
    #[arg(long, env = "CIPHERLINE_RATE_LIMIT", default_value_t = 30)]
    pub rate_limit_per_sec: u32,

    /// Interval (seconds) between expired-message cleanup sweeps.
    #[arg(long, env = "CIPHERLINE_CLEANUP_INTERVAL", default_value_t = 60)]
    pub cleanup_interval_secs: u64,

    /// Maximum queued messages per device before rejecting new ones.
    #[arg(long, env = "CIPHERLINE_MAX_QUEUED", default_value_t = 2_000)]
    pub max_queued_per_device: usize,

    /// Maximum one-time pre-keys stored per device.
    #[arg(long, env = "CIPHERLINE_MAX_OPKS", default_value_t = 200)]
    pub max_opks_per_device: usize,

    /// WebSocket ping interval in seconds.
    #[arg(long, env = "CIPHERLINE_PING_INTERVAL", default_value_t = 30)]
    pub ping_interval_secs: u64,

    /// WebSocket idle timeout in seconds (disconnect after this much silence).
    #[arg(long, env = "CIPHERLINE_IDLE_TIMEOUT", default_value_t = 90)]
    pub idle_timeout_secs: u64,

    /// Authentication challenge timestamp tolerance in seconds.
    #[arg(long, env = "CIPHERLINE_AUTH_TOLERANCE", default_value_t = 60)]
    pub auth_timestamp_tolerance_secs: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            message_ttl_secs: 604_800,
            max_message_size: 65_536,
            max_connections: 10_000,
            rate_limit_per_sec: 30,
            cleanup_interval_secs: 60,
            max_queued_per_device: 2_000,
            max_opks_per_device: 200,
            ping_interval_secs: 30,
            idle_timeout_secs: 90,
            auth_timestamp_tolerance_secs: 60,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RelayConfig::default();
        assert_eq!(config.message_ttl_secs, 604_800);
        assert_eq!(config.max_message_size, 65_536);
        assert_eq!(config.max_connections, 10_000);
        assert_eq!(config.max_queued_per_device, 2_000);
    }
}
