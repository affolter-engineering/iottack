use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use socketcan::{CanFrame, CanSocket, EmbeddedFrame, Socket};
use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, Instant};

use super::common::{format_id, frame_id, hex_bytes, id_severity_high, known_id_hint, IFACE_HELP};

/// CAN bus ID scanning plugin.
pub struct CanScan {
    iface: String,
    duration_secs: u64,
}

/// Default implementation for CanScan.
impl CanScan {
    pub fn new() -> Self {
        Self {
            iface: "can0".into(),
            duration_secs: 5,
        }
    }
}

/// Plugin implementation for CanScan.
impl Default for CanScan {
    fn default() -> Self {
        Self::new()
    }
}

/// Entry for a CAN ID in the scan results.
struct IdEntry {
    count: u64,
    last_data: Vec<u8>,
    dlc: usize,
    extended: bool,
}

/// Plugin implementation for CanScan.
impl Plugin for CanScan {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Discover active CAN IDs on the bus",
            description: "Passively listens on a SocketCAN interface and enumerates every \
                          unique CAN ID that transmits a data frame during the capture window. \
                          Each ID is reported with its frame count, rate, DLC, and last \
                          observed payload. OBD-II diagnostic IDs (0x7DF, 0x7E0-0x7EF) are \
                          flagged as High severity because they expose unauthenticated access \
                          to ECU diagnostics. CANopen management and SDO IDs are flagged \
                          Medium. Extended (29-bit EFF) IDs are listed but not classified - \
                          J1939 PGN decoding is out of scope.",
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
                    name: "duration",
                    short: Some('d'),
                    help: "Scan duration in seconds",
                    value_name: "SECS",
                    default: Some("5"),
                    is_flag: false,
                },
            ],
        )
    }

    /// Initialize the plugin with configuration values.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.iface = config.get_or("iface", "can0");
        self.duration_secs = config.parse_or("duration", 5u64);
        Ok(())
    }

    /// Execute the plugin: scan for active CAN IDs.
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

        socket
            .set_read_timeout(Duration::from_millis(100))
            .map_err(|e| anyhow::anyhow!("set_read_timeout: {e}"))?;

        let deadline = Instant::now() + Duration::from_secs(self.duration_secs);
        let start = Instant::now();

        // BTreeMap keeps IDs in ascending order for deterministic output
        let mut ids: BTreeMap<u32, IdEntry> = BTreeMap::new();

        while Instant::now() < deadline {
            match socket.read_frame() {
                Ok(CanFrame::Data(f)) => {
                    let (num_id, ext) = frame_id(&f);
                    let entry = ids.entry(num_id).or_insert(IdEntry {
                        count: 0,
                        last_data: Vec::new(),
                        dlc: 0,
                        extended: ext,
                    });
                    entry.count += 1;
                    entry.last_data = f.data().to_vec();
                    entry.dlc = f.dlc();
                }
                Ok(_) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // normal poll timeout
                }
                Err(e) => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        "SocketCAN read error",
                        format!("{e}"),
                    ));
                    break;
                }
            }
        }

        let elapsed = start.elapsed().as_secs_f64().max(0.001);

        if ids.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                format!(
                    "No active CAN IDs found on {} in {:.1}s",
                    self.iface, elapsed
                ),
                "No data frames were received. The bus may be idle, disconnected \
                 or at a different bit rate.",
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!(
                "{} unique CAN ID(s) active on {} over {:.1}s",
                ids.len(),
                self.iface,
                elapsed
            ),
            format!(
                "Discovered {} unique CAN IDs transmitting data frames.",
                ids.len()
            ),
        ));

        for (&id, entry) in &ids {
            let id_str = format_id(id, entry.extended);
            let data_hex = hex_bytes(&entry.last_data);
            let rate = entry.count as f64 / elapsed;

            let (sev, type_note) = if entry.extended {
                (Severity::Info, " [EFF/extended 29-bit]".into())
            } else {
                match known_id_hint(id) {
                    Some(hint) if id_severity_high(id) => {
                        (Severity::High, format!(" [{hint}]"))
                    }
                    Some(hint) => (Severity::Medium, format!(" [{hint}]")),
                    None => (Severity::Info, String::new()),
                }
            };

            result.add(
                PluginFinding::new(
                    sev,
                    format!("CAN ID {id_str}{type_note}"),
                    format!(
                        "Frames: {}  Rate: {rate:.1}/s  DLC: {}  Last: [{data_hex}]",
                        entry.count, entry.dlc,
                    ),
                )
                .with_evidence(format!(
                    "id={id_str} count={} rate={rate:.1}/s dlc={} data=[{data_hex}]",
                    entry.count, entry.dlc,
                )),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(CanScan::new()) as Box<dyn crate::Plugin>)
}
