//! GhostESP device information plugin.
//!
//! Connects to a GhostESP device over USB serial, waits for the `ghost>`
//! interactive prompt, then runs `chipinfo` and `devices` to collect ESP32
//! hardware details and the list of Bluetooth / Wi-Fi devices the firmware
//! has seen.  Reports the raw output and flags the presence of a GhostESP
//! pentesting tool as a security finding.

use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use crate::protocols::uart::{UartConfig, UartSession};
use anyhow::Result;
use std::time::{Duration, Instant};

const PROMPT: &str = "ghost>";

/// Remove ANSI CSI escape sequences (ESC [ ... <letter>) from a string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
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

/// Accumulate bytes from the session until `ghost>` appears (after stripping
/// ANSI colour codes) or `timeout_ms` elapses.
/// Returns the stripped content received *before* the prompt.
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

/// Send a command line and return the output up to the next `ghost>` prompt,
/// with the echoed command line stripped from the top.
fn run_cmd(session: &mut UartSession, cmd: &str, timeout_ms: u64) -> Result<String> {
    session.write_line(cmd)?;
    session.flush()?;
    let raw = read_until_prompt(session, timeout_ms)?;
    let output = raw.lines().skip(1).collect::<Vec<_>>().join("\n");
    Ok(output.trim().to_string())
}

fn add_chipinfo_findings(result: &mut PluginResult, output: &str) {
    if output.is_empty() {
        result.add(PluginFinding::new(
            Severity::Info,
            "chipinfo returned no output",
            "The device did not return chip information. \
             It may require a firmware update or the command syntax has changed.",
        ));
        return;
    }

    result.add(
        PluginFinding::new(Severity::Info, "GhostESP chip information", output)
            .with_evidence(output.to_string()),
    );
}

fn add_devices_findings(result: &mut PluginResult, output: &str) {
    if output.is_empty() {
        result.add(PluginFinding::new(
            Severity::Info,
            "No devices listed",
            "The `devices` command returned no output.",
        ));
        return;
    }

    // Count enabled peripheral entries — each is indented with two spaces.
    let count = output
        .lines()
        .filter(|l| l.starts_with("  ") && !l.trim().is_empty())
        .count();

    result.add(
        PluginFinding::new(
            Severity::Info,
            if count > 0 {
                format!("{count} enabled peripheral(s) on GhostESP device")
            } else {
                "GhostESP enabled devices".to_string()
            },
            output,
        )
        .with_evidence(output.to_string()),
    );
}

/// Plugin implementation for GhostESP devices.
pub struct DevicePlugin {
    port: String,
    baud_rate: u32,
    timeout_ms: u64,
}

/// Device plugin constructor and default implementation.
impl DevicePlugin {
    pub fn new() -> Self {
        Self {
            port: String::new(),
            baud_rate: 115_200,
            timeout_ms: 5_000,
        }
    }
}

/// Default implementation for the device plugin.
impl Default for DevicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin trait implementation for the device plugin.
impl Plugin for DevicePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Connect to a GhostESP device and report chip and device information",
            description: "Opens a serial connection to a GhostESP device, waits for the \
                          interactive 'ghost>' prompt, then executes 'chipinfo' to retrieve \
                          ESP32 hardware details and 'devices' to list Bluetooth and Wi-Fi \
                          devices the firmware has observed. Reports chip identity, firmware \
                          version, and the full device inventory as structured findings.",
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
                    help: "Per-command response timeout in ms (default 5000).",
                    value_name: "MS",
                    default: Some("5000"),
                    is_flag: false,
                },
            ],
        )
    }

    /// Initialize the device plugin with the provided configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.port = config.require("port")?.to_string();
        self.baud_rate = config.parse_or("baud_rate", 115_200u32);
        self.timeout_ms = config.parse_or("timeout_ms", 5_000u64);
        Ok(())
    }

    /// Execute the device plugin, performing the GhostESP interaction and collecting findings.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        // Use a short per-read timeout so read_until_prompt can poll within
        // the overall deadline rather than blocking for the full timeout_ms
        // on a single read call.
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

        // GhostESP requires a newline to emit the prompt (LF, matching what a
        // Unix terminal sends when the user presses Enter).
        session.write_bytes(b"\n")?;
        session.flush()?;

        match read_until_prompt(&mut session, self.timeout_ms) {
            Err(e) => {
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
            Ok(_) => {}
        }

        // GhostESP command: chipinfo
        match run_cmd(&mut session, "chipinfo", self.timeout_ms) {
            Ok(output) => add_chipinfo_findings(&mut result, &output),
            Err(e) => result.add(PluginFinding::new(
                Severity::Info,
                "chipinfo command failed",
                e.to_string(),
            )),
        }

        // GhostESP command: devices
        match run_cmd(&mut session, "devices", self.timeout_ms) {
            Ok(output) => add_devices_findings(&mut result, &output),
            Err(e) => result.add(PluginFinding::new(
                Severity::Info,
                "devices command failed",
                e.to_string(),
            )),
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(DevicePlugin::new()) as Box<dyn crate::Plugin>)
}
