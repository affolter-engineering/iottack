use crate::core::PluginConfig;
use anyhow::Result;
use serialport::{DataBits, Parity, StopBits};

/// Configuration for a UART connection.
#[derive(Debug, Clone)]
pub struct UartConfig {
    pub port: String,
    pub baud_rate: u32,
    pub data_bits: DataBits,
    pub stop_bits: StopBits,
    pub parity: Parity,
    /// Per-read timeout in milliseconds.
    pub timeout_ms: u64,
}

/// Default configuration for a UART connection.
impl Default for UartConfig {
    fn default() -> Self {
        Self {
            port: String::new(),
            baud_rate: 115_200,
            data_bits: DataBits::Eight,
            stop_bits: StopBits::One,
            parity: Parity::None,
            timeout_ms: 500,
        }
    }
}

/// Construct a `UartConfig` from a `PluginConfig`.
impl UartConfig {
    pub fn from_plugin_config(config: &PluginConfig) -> Result<Self> {
        Ok(Self {
            port: config.require("port")?.to_string(),
            baud_rate: config.parse_or("baud_rate", 115_200),
            data_bits: DataBits::Eight,
            stop_bits: StopBits::One,
            parity: Parity::None,
            timeout_ms: config.parse_or("timeout_ms", 500u64),
        })
    }
}
