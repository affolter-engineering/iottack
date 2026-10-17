use super::{SerialPlugin, UartConfig, UartSession};
use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;

/// Standard UART baud rates to probe, ordered from most common to least.
const BAUD_CANDIDATES: &[u32] = &[
    115_200, 57_600, 38_400, 19_200, 9_600, 4_800, 2_400, 1_200, 230_400, 460_800, 921_600, 300,
];

/// Minimum fraction of bytes that must be printable ASCII for a baud rate to
/// be considered valid (0.0–1.0).
const PRINTABLE_THRESHOLD: f32 = 0.70;

/// Probe every common UART baud rate and report which ones produce readable
/// ASCII output. Useful as a first step when analyzing an unknown UART header.
pub struct BaudRateScanner {
    config: UartConfig,
    session: Option<UartSession>,
    /// Stimulus sent at each baud rate to elicit a response.
    stimulus: Vec<u8>,
}

impl BaudRateScanner {
    pub fn new() -> Self {
        Self {
            config: UartConfig::default(),
            session: None,
            // Two newlines and "AT" covers most boot loaders and modems.
            stimulus: b"\r\n\r\nAT\r\n".to_vec(),
        }
    }

    fn is_likely_ascii(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let printable = data
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || matches!(b, b'\t' | b'\r' | b'\n' | b' '))
            .count();
        printable as f32 / data.len() as f32 >= PRINTABLE_THRESHOLD
    }
}

impl Plugin for BaudRateScanner {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Probe common UART baud rates to identify the active configuration",
            description: "Opens the target serial port at each standard baud rate, sends a \
                          stimulus and checks whether the response is printable ASCII. \
                        Reports all baud rates that produce readable output.",
            needs_root: false,
            args: &[
                CliArg { name: "port", short: Some('p'), help: "Serial port (e.g., /dev/ttyUSB0)", value_name: "PATH", default: None, is_flag: false },
                CliArg { name: "timeout_ms", short: None, help: "Read timeout per baud rate (ms)", value_name: "MS",   default: Some("500"), is_flag: false },
            ],
        )
    }

    /// Initialize the baud rate scanner with the given plugin configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        // Re-read config so port/timeout overrides from the CLI are picked up.
        self.config = UartConfig::from_plugin_config(config)?;
        Ok(())
    }

    ///
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        let mut hits: Vec<u32> = Vec::new();

        for &baud in BAUD_CANDIDATES {
            let mut cfg = self.config.clone();
            cfg.baud_rate = baud;

            let session = match UartSession::open(&cfg) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(baud, error = %e, "could not open port");
                    continue;
                }
            };
            self.session = Some(session);

            if let Some(s) = &mut self.session {
                let _ = s.write_bytes(&self.stimulus);
                let _ = s.flush();
            }

            let data = self
                .session
                .as_mut()
                .map(|s| s.drain())
                .transpose()?
                .unwrap_or_default();
            tracing::debug!(baud, bytes = data.len(), "received");

            if Self::is_likely_ascii(&data) {
                let preview: String = data
                    .iter()
                    .take(80)
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();

                result.add(
                    PluginFinding::new(
                        Severity::High,
                        format!("UART active at {baud} baud"),
                        format!(
                            "Port {} responded with readable ASCII at {baud} baud.",
                            self.config.port
                        ),
                    )
                    .with_evidence(preview),
                );
                hits.push(baud);
            }

            self.session = None; // close before reopening at next baud
        }

        if hits.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No readable UART output detected",
                "None of the probed baud rates produced printable ASCII. \
                 The device may be powered off, the port name may be wrong, \
                 or a non-standard baud rate is in use.",
            ));
            result.finish(PluginStatus::Fail);
        } else {
            result.finish(PluginStatus::Pass);
        }

        Ok(result)
    }

    fn teardown(&mut self) -> Result<()> {
        self.session = None;
        Ok(())
    }
}

/// Default implementation for the BaudRateScanner plugin.
impl Default for BaudRateScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialPlugin for BaudRateScanner {
    fn serial_config(&self) -> &UartConfig {
        &self.config
    }
    fn session(&self) -> Option<&UartSession> {
        self.session.as_ref()
    }
    fn session_mut(&mut self) -> Option<&mut UartSession> {
        self.session.as_mut()
    }
    fn set_session(&mut self, s: Option<UartSession>) {
        self.session = s;
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(BaudRateScanner::new()) as Box<dyn crate::Plugin>)
}
