use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use crate::protocols::uart::{UartConfig, UartSession};
use anyhow::Result;
use std::time::{Duration, Instant};

const PROMPT: &str = "ghost>";

/// Strips ANSI escape codes from a string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// BLE detection plugin for GhostESP devices.
fn read_until_prompt(session: &mut UartSession, timeout_ms: u64) -> Result<String> {
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!(
                "timed out after {} ms waiting for '{}' prompt",
                timeout_ms,
                PROMPT
            );
        }
        let bytes = session.read_bytes(512)?;
        if bytes.is_empty() {
            continue;
        }
        buf.push_str(&String::from_utf8_lossy(&bytes));
        let clean = strip_ansi(&buf);
        if let Some(pos) = clean.rfind(PROMPT) {
            return Ok(clean[..pos].trim().to_string());
        }
    }
}

/// Runs a command on the UART session and returns the output, excluding the echoed command line.
fn run_cmd(session: &mut UartSession, cmd: &str, timeout_ms: u64) -> Result<String> {
    session.write_line(cmd)?;
    session.flush()?;
    let raw = read_until_prompt(session, timeout_ms)?;
    let output = raw.lines().skip(1).collect::<Vec<_>>().join("\n");
    Ok(output.trim().to_string())
}

/// Reads from the UART session for the specified duration, returning all collected output.
fn read_for_duration(session: &mut UartSession, duration_ms: u64) -> String {
    let mut buf = String::new();
    let deadline = Instant::now() + Duration::from_millis(duration_ms);
    while Instant::now() < deadline {
        if let Ok(bytes) = session.read_bytes(512) {
            if !bytes.is_empty() {
                buf.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
    }
    strip_ansi(&buf)
}

/// Represents a detected BLE device with its name, optional variant, MAC address and RSSI.
struct BleDevice {
    name: String,
    variant: Option<String>,
    mac: String,
    rssi: String,
}

/// Parse one device line from `bledetect -l`.
///
/// Accepts both `[N] Name (Variant) | MAC | RSSI` and `[N] Name | MAC | RSSI`.
fn parse_device_line(line: &str) -> Option<BleDevice> {
    let parts: Vec<&str> = line.splitn(3, '|').collect();
    if parts.len() != 3 {
        return None;
    }
    let name_raw = parts[0].trim();
    let mac = parts[1].trim().to_string();
    let rssi = parts[2].trim().to_string();

    // Strip the "[N] " index prefix.
    let name_part = name_raw.find(']').map(|pos| name_raw[pos + 1..].trim())?;

    let (name, variant) = if name_part.ends_with(')') {
        if let Some(paren) = name_part.rfind('(') {
            let n = name_part[..paren].trim().to_string();
            let v = name_part[paren + 1..name_part.len() - 1].trim().to_string();
            (n, Some(v))
        } else {
            (name_part.to_string(), None)
        }
    } else {
        (name_part.to_string(), None)
    };

    Some(BleDevice {
        name,
        variant,
        mac,
        rssi,
    })
}

/// Determines the severity level for a detected BLE device based on its name and variant.
fn severity_for_device(name: &str, variant: Option<&str>) -> Severity {
    let n = name.to_lowercase();
    let v = variant.map(|s| s.to_lowercase()).unwrap_or_default();
    if n.contains("skimmer") {
        Severity::High
    } else if n.contains("airtag")
        || n.contains("tracker")
        || n.contains("tile")
        || n.contains("google tag")
        || v == "find my"
        || v.contains("tracker")
    {
        Severity::Medium
    } else if n.contains("beacon") || v.contains("beacon") {
        Severity::Low
    } else {
        Severity::Info
    }
}

/// BLE detection plugin implementation for GhostESP devices.
pub struct BleDetectPlugin {
    port: String,
    baud_rate: u32,
    timeout_ms: u64,
    duration_secs: u64,
}

/// Constructs a new instance of the BLE detection plugin with default settings.
impl BleDetectPlugin {
    pub fn new() -> Self {
        Self {
            port: String::new(),
            baud_rate: 115_200,
            timeout_ms: 5_000,
            duration_secs: 15,
        }
    }
}

/// Provides a default instance of the BLE detection plugin.
impl Default for BleDetectPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements the Plugin trait for the BLE detection plugin.
impl Plugin for BleDetectPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Detect BLE trackers, skimmers and beacons via a GhostESP device",
            description: "Opens a serial connection to a GhostESP device, waits for the \
                          'ghost>' prompt, starts 'bledetect' to scan for trackers, skimmers \
                          and beacons by signature, waits for the configured duration, then \
                          queries 'bledetect -l' (device list) and 'bledetect -i' (scan state) \
                          before stopping the scan. Each discovered device is reported as a \
                          separate finding with severity scaled by device type: skimmers are \
                          High, trackers and AirTags are Medium, beacons are Low.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "port",
                    short: Some('p'),
                    help: "Serial port the GhostESP device is connected to (e.g., /dev/ttyUSB0).",
                    value_name: "PORT",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "duration",
                    short: Some('d'),
                    help: "Scan duration in seconds before querying results (default 15).",
                    value_name: "SECS",
                    default: Some("15"),
                    is_flag: false,
                },
                CliArg {
                    name: "baud_rate",
                    short: Some('b'),
                    help: "Serial baud rate (default 115200).",
                    value_name: "BAUD",
                    default: Some("115200"),
                    is_flag: false,
                },
                CliArg {
                    name: "timeout_ms",
                    short: Some('t'),
                    help: "Prompt wait timeout in ms (default 5000).",
                    value_name: "MS",
                    default: Some("5000"),
                    is_flag: false,
                },
            ],
        )
    }

    /// Initializes the BLE detection plugin with the provided configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.port = config.require("port")?.to_string();
        self.duration_secs = config.parse_or("duration", 15u64);
        self.baud_rate = config.parse_or("baud_rate", 115_200u32);
        self.timeout_ms = config.parse_or("timeout_ms", 5_000u64);
        Ok(())
    }

    /// Executes the BLE detection scan using the current plugin configuration.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let uart_cfg = UartConfig {
            port: self.port.clone(),
            baud_rate: self.baud_rate,
            timeout_ms: 100,
            ..UartConfig::default()
        };

        let mut session = match UartSession::open(&uart_cfg) {
            Ok(s) => s,
            Err(e) => {
                let msg = e.to_string();
                let hint = if msg.contains("No such file") {
                    " Run `iottack uart port-scan` to list available ports."
                } else {
                    " Check that your user is in the `dialout` group."
                };
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot open {}", self.port),
                    format!("{msg}.{hint}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        session.write_bytes(b"\n")?;
        session.flush()?;

        if let Err(e) = read_until_prompt(&mut session, self.timeout_ms) {
            result.add(PluginFinding::new(
                Severity::Info,
                "GhostESP prompt not found",
                format!(
                    "{e}. Ensure the device is running GhostESP firmware and \
                     connected at {baud} baud.",
                    baud = self.baud_rate
                ),
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        // Start the background scan and consume the immediate response.
        session.write_line("bledetect")?;
        session.flush()?;
        let _ = read_until_prompt(&mut session, self.timeout_ms);

        // Let the scan run. Also drain any unsolicited notifications.
        let _streaming = read_for_duration(&mut session, self.duration_secs * 1_000);

        // Query the structured device list and scan state.
        let listing = match run_cmd(&mut session, "bledetect -l", self.timeout_ms) {
            Ok(out) => out,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "bledetect -l failed",
                    e.to_string(),
                ));
                String::new()
            }
        };

        // Stop the scan.
        let _ = run_cmd(&mut session, "bledetect -s", self.timeout_ms);

        // Parse and report each discovered device as its own finding.
        let devices: Vec<BleDevice> = listing.lines().filter_map(parse_device_line).collect();

        if devices.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No BLE trackers, skimmers or beacons detected",
                format!(
                    "bledetect ran for {} s and found no devices matching known signatures.",
                    self.duration_secs
                ),
            ));
        } else {
            for dev in devices {
                let sev = severity_for_device(&dev.name, dev.variant.as_deref());
                let title = if sev >= Severity::Medium {
                    format!("Suspicious BLE device: {}", dev.name)
                } else {
                    format!("BLE device: {}", dev.name)
                };
                let mut body = format!(
                    "Type: {}\n  MAC address: {}\n  RSSI: {}",
                    dev.name, dev.mac, dev.rssi
                );
                if let Some(ref v) = dev.variant {
                    body.push_str(&format!("\n  Variant: {v}"));
                }
                result.add(PluginFinding::new(sev, title, &body).with_evidence(body.clone()));
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(BleDetectPlugin::new()) as Box<dyn crate::Plugin>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_device_with_variant() {
        let d =
            parse_device_line("  [1] Apple Watch (Watch) | D5:E4:39:C9:B3:1C | -82 dBm").unwrap();
        assert_eq!(d.name, "Apple Watch");
        assert_eq!(d.variant.as_deref(), Some("Watch"));
        assert_eq!(d.mac, "D5:E4:39:C9:B3:1C");
        assert_eq!(d.rssi, "-82 dBm");
    }

    #[test]
    fn parse_device_without_variant() {
        let d = parse_device_line("  [5] AirTag | 63:9C:18:51:12:D4 | -85 dBm").unwrap();
        assert_eq!(d.name, "AirTag");
        assert_eq!(d.variant, None);
        assert_eq!(d.mac, "63:9C:18:51:12:D4");
        assert_eq!(d.rssi, "-85 dBm");
    }

    #[test]
    fn parse_device_find_my_variant() {
        let d =
            parse_device_line("  [3] Google Tag (Find My) | 80:90:0D:40:BE:7E | -55 dBm").unwrap();
        assert_eq!(d.name, "Google Tag");
        assert_eq!(d.variant.as_deref(), Some("Find My"));
        assert_eq!(
            severity_for_device(&d.name, d.variant.as_deref()),
            Severity::Medium
        );
    }

    #[test]
    fn parse_skips_header_line() {
        assert!(parse_device_line("--- BLE Devices (11) ---").is_none());
    }

    #[test]
    fn severity_airtag_is_medium() {
        assert_eq!(severity_for_device("AirTag", None), Severity::Medium);
    }

    #[test]
    fn severity_skimmer_is_high() {
        assert_eq!(severity_for_device("BLE Skimmer", None), Severity::High);
    }
}
