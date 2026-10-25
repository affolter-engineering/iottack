use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use crate::protocols::uart::{UartConfig, UartSession};
use anyhow::Result;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Reads from the UART session until the GhostESP prompt is encountered or the timeout is reached. Returns the captured output without the prompt.
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

/// Reads from the UART session until the GhostESP prompt is encountered or the timeout is reached. Returns the captured output without the prompt.
pub struct BleScanPlugin {
    port: String,
    baud_rate: u32,
    timeout_ms: u64,
    mode: String,
    filter: String,
    duration_secs: u64,
}

/// BLE scan plugin for GhostESP devices. Configures and executes BLE scans over a serial connection.
impl BleScanPlugin {
    pub fn new() -> Self {
        Self {
            port: String::new(),
            baud_rate: 115_200,
            timeout_ms: 5_000,
            mode: String::new(),
            filter: String::new(),
            duration_secs: 0,
        }
    }

    fn build_command(&self) -> String {
        match self.mode.as_str() {
            "flipper" => "blescan -f".to_string(),
            "spam-detector" => "blescan -ds".to_string(),
            "airtag" => "blescan -a".to_string(),
            "advertiser" => "blescan -adv".to_string(),
            "oui" => format!("blescan -oui {}", self.filter),
            "vendor" => format!("blescan -vendor {}", self.filter),
            "gatt" => "blescan -g".to_string(),
            "raw" => "blescan -r".to_string(),
            _ => "blescan -adv".to_string(),
        }
    }
}

/// Provides a default implementation for the BLE scan plugin.
impl Default for BleScanPlugin {
    fn default() -> Self {
        Self::new()
    }
}

///
impl Plugin for BleScanPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Run a BLE scan on a GhostESP device and stream results to the terminal",
            description: "Opens a serial connection to a GhostESP device, waits for the \
                          'ghost>' prompt, starts a BLE scan in the chosen mode, and mirrors \
                          all device output to the terminal in real time. Press Ctrl+D to stop \
                          scanning; the plugin then sends 'blescan -s', waits for the prompt, \
                          and reports everything collected as findings. \
                          Modes: flipper, spam-detector, airtag, advertiser, oui, vendor, gatt, raw.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "port",
                    short: Some('p'),
                    help: "Serial port the GhostESP device is connected to (e.g., /dev/ttyACM0).",
                    value_name: "PORT",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "mode",
                    short: Some('m'),
                    help: "Scan mode: flipper, spam-detector, airtag, advertiser, oui, vendor, gatt, raw.",
                    value_name: "MODE",
                    default: Some("advertiser"),
                    is_flag: false,
                },
                CliArg {
                    name: "filter",
                    short: None,
                    help: "OUI prefix or vendor name (required for oui/vendor modes).",
                    value_name: "VALUE",
                    default: Some(""),
                    is_flag: false,
                },
                CliArg {
                    name: "duration",
                    short: Some('d'),
                    help: "Maximum scan duration in seconds; 0 runs until Ctrl+D (default 0).",
                    value_name: "SECS",
                    default: Some("0"),
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

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.port = config.require("port")?.to_string();
        self.mode = config.get_or("mode", "advertiser");
        self.filter = config.get_or("filter", "");
        self.duration_secs = config.parse_or("duration", 0u64);
        self.baud_rate = config.parse_or("baud_rate", 115_200u32);
        self.timeout_ms = config.parse_or("timeout_ms", 5_000u64);

        if (self.mode == "oui" || self.mode == "vendor") && self.filter.is_empty() {
            anyhow::bail!("--filter is required for mode '{}'", self.mode);
        }
        Ok(())
    }

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

        let cmd = self.build_command();
        session.write_line(&cmd)?;
        session.flush()?;

        // Spawn a thread that sets the stop flag when stdin reaches EOF (Ctrl+D).
        let stop = Arc::new(AtomicBool::new(false));
        let stop_stdin = Arc::clone(&stop);
        let _stdin_watcher = std::thread::spawn(move || {
            let mut buf = [0u8; 1];
            loop {
                match std::io::stdin().read(&mut buf) {
                    Ok(0) | Err(_) => {
                        stop_stdin.store(true, Ordering::Relaxed);
                        break;
                    }
                    Ok(_) => {}
                }
            }
        });

        let deadline = (self.duration_secs > 0)
            .then(|| Instant::now() + Duration::from_secs(self.duration_secs));

        let mut collected = String::new();
        let mut line_buf = String::new();

        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if deadline.map_or(false, |d| Instant::now() >= d) {
                break;
            }

            if let Ok(bytes) = session.read_bytes(512) {
                if !bytes.is_empty() {
                    line_buf.push_str(&strip_ansi(&String::from_utf8_lossy(&bytes)));

                    // Flush complete lines to stdout and accumulate for findings.
                    while let Some(pos) = line_buf.find('\n') {
                        let line = line_buf[..pos].trim().to_string();
                        line_buf.drain(..=pos);
                        if !line.is_empty()
                            && !line.contains(PROMPT)
                            && line != cmd
                            && !line.starts_with("scan_active=")
                        {
                            println!("{line}");
                            collected.push_str(&line);
                            collected.push('\n');
                        }
                    }
                }
            }
        }

        session.write_line("blescan -s")?;
        session.flush()?;
        let _ = read_until_prompt(&mut session, self.timeout_ms);

        let observations: Vec<&str> = collected.lines().filter(|l| !l.trim().is_empty()).collect();

        if observations.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No BLE devices detected ({} mode)", self.mode),
                format!("No devices observed during {} scan.", self.mode),
            ));
        } else {
            let body = observations.join("\n");
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    format!(
                        "{} BLE observation(s) - {} mode",
                        observations.len(),
                        self.mode
                    ),
                    &body,
                )
                .with_evidence(body),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(BleScanPlugin::new()) as Box<dyn crate::Plugin>)
}
