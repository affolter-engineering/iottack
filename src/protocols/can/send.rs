use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use socketcan::{CanDataFrame, CanFrame, CanSocket, EmbeddedFrame, ExtendedId, Socket, StandardId};
use std::thread;
use std::time::Duration;

use super::common::{format_id, hex_bytes, IFACE_HELP};

/// CAN bus frame sending plugin implementation.
pub struct CanSend {
    iface: String,
    id: u32,
    extended: bool,
    data: Vec<u8>,
    count: u32,
    interval_ms: u64,
}

/// CAN bus frame sending plugin structure.
impl CanSend {
    pub fn new() -> Self {
        Self {
            iface: "can0".into(),
            id: 0,
            extended: false,
            data: Vec::new(),
            count: 1,
            interval_ms: 0,
        }
    }
}

/// CAN bus frame sending plugin.
impl Default for CanSend {
    fn default() -> Self {
        Self::new()
    }
}

/// Default implementation for CanSend.
impl Plugin for CanSend {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Send CAN frames to the bus",
            description: "Constructs and transmits one or more CAN data frames via a \
                          SocketCAN interface. Accepts standard 11-bit IDs (SFF, up to \
                          0x7FF) and extended 29-bit IDs (EFF, up to 0x1FFFFFFF). IDs \
                          greater than 0x7FF are automatically treated as EFF. Data is \
                          supplied as hex bytes in any common notation (space-separated, \
                          colon-separated, or compact). Repeating the same frame at an \
                          interval is supported for keep-alive or fuzzing workflows. \
                          Requires a configured and active SocketCAN interface.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "iface",
                    short: Some('i'),
                    help: "SocketCAN interface name (e.g., can0, vcan0)",
                    value_name: "IFACE",
                    default: Some("can0"),
                    is_flag: false,
                },
                CliArg {
                    name: "id",
                    short: None,
                    help: "CAN ID in HEX without 0x prefix (e.g., 7DF or 18DB33F1). \
                           IDs > 0x7FF are treated as 29-bit EFF automatically",
                    value_name: "HEX",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "data",
                    short: None,
                    help: "Payload bytes in HEX, any separator accepted \
                           (e.g., \"02 01 00\" or \"020100\" or \"02:01:00\"), max 8 bytes",
                    value_name: "HEX",
                    default: Some(""),
                    is_flag: false,
                },
                CliArg {
                    name: "extended",
                    short: Some('e'),
                    help: "Force 29-bit extended frame format (EFF) even for IDs <= 0x7FF",
                    value_name: "",
                    default: None,
                    is_flag: true,
                },
                CliArg {
                    name: "count",
                    short: Some('n'),
                    help: "Number of frames to send",
                    value_name: "N",
                    default: Some("1"),
                    is_flag: false,
                },
                CliArg {
                    name: "interval_ms",
                    short: None,
                    help: "Delay between consecutive frames in milliseconds",
                    value_name: "MS",
                    default: Some("0"),
                    is_flag: false,
                },
            ],
        )
    }

    /// Initialize the plugin with configuration values.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.iface = config.get_or("iface", "can0");

        let id_str = config.require("id")?;
        let id_stripped = id_str.trim_start_matches("0x").trim_start_matches("0X");
        self.id = u32::from_str_radix(id_stripped, 16)
            .map_err(|_| anyhow::anyhow!("invalid CAN ID '{}': expected hex digits", id_str))?;

        self.extended = config.get("extended") == Some("true") || self.id > 0x7FF;

        let data_str = config.get_or("data", "");
        self.data = parse_hex_bytes(&data_str)
            .map_err(|e| anyhow::anyhow!("invalid --data: {e}"))?;

        if self.data.len() > 8 {
            return Err(anyhow::anyhow!(
                "--data has {} bytes; CAN classic frames carry at most 8",
                self.data.len()
            ));
        }

        self.count = config.parse_or("count", 1u32);
        self.interval_ms = config.parse_or("interval_ms", 0u64);

        Ok(())
    }

    /// Execute the plugin: send CAN frames.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let socket = match CanSocket::open(&self.iface) {
            Ok(s) => s,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot open CAN interface {}", self.iface),
                    format!("{e}\n\n{IFACE_HELP}"),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        let frame = match build_frame(self.id, self.extended, &self.data) {
            Ok(f) => f,
            Err(e) => {
                result.add(PluginFinding::new(Severity::Info, "Invalid frame parameters", format!("{e}")));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        let id_str = format_id(self.id, self.extended);
        let data_hex = hex_bytes(&self.data);
        let fmt = if self.extended { "EFF/29-bit" } else { "SFF/11-bit" };

        let mut sent = 0u32;
        let mut errors = 0u32;

        for i in 0..self.count {
            if i > 0 && self.interval_ms > 0 {
                thread::sleep(Duration::from_millis(self.interval_ms));
            }
            match socket.write_frame(&frame) {
                Ok(()) => {
                    sent += 1;
                    tracing::debug!(id = %id_str, seq = i, "CAN frame sent");
                }
                Err(e) => {
                    errors += 1;
                    tracing::warn!(id = %id_str, seq = i, "write_frame: {e}");
                }
            }
        }

        if sent == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("Failed to send frame {id_str} ({errors} error(s))"),
                format!("All {errors} write attempt(s) failed on {}.", self.iface),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    format!("Sent {sent}/{} frame(s): {id_str} [{data_hex}]", self.count),
                    format!(
                        "Interface : {}\n  \
                         ID        : {id_str} ({fmt})\n  \
                         Payload   : [{data_hex}] ({} byte(s))\n  \
                         Sent      : {sent}  Errors: {errors}",
                        self.iface,
                        self.data.len(),
                    ),
                )
                .with_evidence(format!(
                    "iface={} id={id_str} fmt={fmt} data=[{data_hex}] sent={sent} errors={errors}",
                    self.iface,
                )),
            );
            result.finish(PluginStatus::Pass);
        }

        Ok(result)
    }
}

/// Build a CAN frame (standard or extended) with the given ID and data.
fn build_frame(id: u32, extended: bool, data: &[u8]) -> Result<CanFrame> {
    if extended {
        let eid = ExtendedId::new(id).ok_or_else(|| {
            anyhow::anyhow!(
                "ID 0x{id:08X} out of range for 29-bit EFF (max 0x1FFFFFFF)"
            )
        })?;
        CanDataFrame::new(eid, data)
            .map(CanFrame::Data)
            .ok_or_else(|| anyhow::anyhow!("failed to build EFF frame (data too long?)"))
    } else {
        let sid = StandardId::new(id as u16).ok_or_else(|| {
            anyhow::anyhow!(
                "ID 0x{id:03X} out of range for 11-bit SFF (max 0x7FF)"
            )
        })?;
        CanDataFrame::new(sid, data)
            .map(CanFrame::Data)
            .ok_or_else(|| anyhow::anyhow!("failed to build SFF frame (data too long?)"))
    }
}

/// Parse hex bytes from space-, colon-, comma-separated or compact HEX strings.
fn parse_hex_bytes(s: &str) -> std::result::Result<Vec<u8>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let digits: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.len() % 2 != 0 {
        return Err(format!("odd number of HEX digits in '{s}'"));
    }
    digits
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
                .map_err(|e| e.to_string())
        })
        .collect()
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(CanSend::new()) as Box<dyn crate::Plugin>)
}
