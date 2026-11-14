use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use socketcan::{CanFrame, CanSocket, EmbeddedFrame, Socket};
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use super::common::{format_id, frame_id, hex_bytes, id_severity_high, known_id_hint, IFACE_HELP};

/// CAN bus traffic capture and analysis plugin.
pub struct CanDump {
    iface: String,
    duration_secs: u64,
    max_frames: usize,
}

/// 
impl CanDump {
    pub fn new() -> Self {
        Self {
            iface: "can0".into(),
            duration_secs: 10,
            max_frames: 10_000,
        }
    }
}

/// Default implementation for CanDump.
impl Default for CanDump {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin implementation for CanDump.
impl Plugin for CanDump {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Capture and analyze CAN bus traffic",
            description: "Passively captures CAN frames from a SocketCAN interface for a \
                          configurable duration and reports traffic statistics: total frame \
                          count, frame rate, unique IDs, error frames and the top IDs by \
                          volume. Security-relevant IDs (OBD-II diagnostics at 0x7DF/0x7E0-\
                          0x7EF, CANopen SDO at 0x580-0x67F) are flagged with elevated \
                          severity. Requires a configured and active SocketCAN interface \
                          (can0, vcan0, etc.).",
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
                    help: "Capture duration in seconds",
                    value_name: "SECS",
                    default: Some("10"),
                    is_flag: false,
                },
                CliArg {
                    name: "max_frames",
                    short: None,
                    help: "Maximum frames to capture before stopping early",
                    value_name: "N",
                    default: Some("10000"),
                    is_flag: false,
                },
            ],
        )
    }

    /// Initialize the plugin with configuration values.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.iface = config.get_or("iface", "can0");
        self.duration_secs = config.parse_or("duration", 10u64);
        self.max_frames = config.parse_or("max_frames", 10_000usize);
        Ok(())
    }

    /// Execute the plugin: capture and analyze CAN traffic.
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

        // id -> (count, last_data, last_dlc, is_extended)
        let mut id_stats: HashMap<u32, (u64, Vec<u8>, usize, bool)> = HashMap::new();
        let mut total: u64 = 0;
        let mut error_count: u64 = 0;

        while Instant::now() < deadline && (total as usize) < self.max_frames {
            match socket.read_frame() {
                Ok(CanFrame::Data(f)) => {
                    total += 1;
                    let (num_id, ext) = frame_id(&f);
                    let entry = id_stats
                        .entry(num_id)
                        .or_insert((0, Vec::new(), 0, ext));
                    entry.0 += 1;
                    entry.1 = f.data().to_vec();
                    entry.2 = f.dlc();
                }
                Ok(CanFrame::Remote(_)) => {
                    total += 1;
                }
                Ok(CanFrame::Error(_)) => {
                    error_count += 1;
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // poll timeout — check deadline and continue
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
        let fps = total as f64 / elapsed;
        let unique_ids = id_stats.len();

        if total == 0 && error_count == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No CAN frames received on {} in {:.1}s", self.iface, elapsed),
                "The bus may be idle, disconnected or at a different bit rate. \
                 Verify wiring and that the interface bit rate matches the bus.",
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!(
                "{}: {} frame(s), {} unique ID(s) in {:.1}s ({:.1} fps)",
                self.iface, total, unique_ids, elapsed, fps
            ),
            format!(
                "Data frames: {total}\nFrame rate: {fps:.1}/s\n\
                 Unique IDs: {unique_ids}\nError frames: {error_count}"
            ),
        ));

        if error_count > 0 {
            result.add(PluginFinding::new(
                Severity::Low,
                format!("{error_count} CAN error frame(s) on {}", self.iface),
                "Error frames indicate bus-off events, bit errors or CRC errors. \
                 This may signal a bit-rate mismatch, damaged wiring or active \
                 fault injection.",
            ));
        }

        // Top IDs by volume
        let mut sorted: Vec<_> = id_stats.iter().collect();
        sorted.sort_by(|(_, (c1, _, _, _)), (_, (c2, _, _, _))| c2.cmp(c1));

        let top_n = sorted.len().min(10);
        let mut top_lines: Vec<String> = Vec::with_capacity(top_n);
        for (id, (count, data, dlc, ext)) in sorted.iter().take(top_n) {
            top_lines.push(format!(
                "  {}  count={:<6} dlc={}  last=[{}]",
                format_id(**id, *ext),
                count,
                dlc,
                hex_bytes(data),
            ));
        }

        result.add(
            PluginFinding::new(
                Severity::Info,
                format!("Top {} CAN ID(s) by volume on {}", top_n, self.iface),
                top_lines.join("\n"),
            )
            .with_evidence(top_lines.join("\n")),
        );

        // Flag security-relevant IDs
        for (id, (count, data, dlc, ext)) in &id_stats {
            if *ext {
                continue; // J1939/EFF identification is out of scope here
            }
            if let Some(hint) = known_id_hint(*id) {
                let sev = if id_severity_high(*id) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let id_str = format_id(*id, false);
                result.add(
                    PluginFinding::new(
                        sev,
                        format!("Notable CAN ID {id_str}: {hint}"),
                        format!(
                            "ID {id_str} seen {count} time(s). Last frame: dlc={dlc} data=[{}]",
                            hex_bytes(data)
                        ),
                    )
                    .with_evidence(format!(
                        "id={id_str} count={count} dlc={dlc} data=[{}]",
                        hex_bytes(data)
                    )),
                );
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(CanDump::new()) as Box<dyn crate::Plugin>)
}
