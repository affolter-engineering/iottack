use super::{SerialPlugin, UartConfig, UartSession};
use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;

/// Patterns that indicate an interactive shell or login prompt.
const SHELL_PATTERNS: &[&str] = &[
    "login:",
    "Login:",
    "Password:",
    "password:",
    "# ",
    "$ ",
    "> ",
    "bash",
    "sh-",
    "ash",
    "busybox",
    "root@",
    "admin@",
    "BusyBox",
    "U-Boot",
    "Press ENTER",
    "press enter",
    "Hit any key",
];

/// Patterns that suggest a device is booting (not yet at a shell).
const BOOT_PATTERNS: &[&str] = &[
    "Booting", "booting", "Starting", "Loading", "Kernel", "U-Boot", "GRUB", "init:", "systemd",
];

/// Connect at a known baud rate and detect whether the device exposes
/// an interactive shell or login prompt over the serial link.
pub struct ShellDetector {
    config: UartConfig,
    session: Option<UartSession>,
    /// Number of stimulus attempts before giving up.
    attempts: u8,
}

/// Default implementation for the ShellDetector plugin.
impl ShellDetector {
    pub fn new() -> Self {
        Self {
            config: UartConfig::default(),
            session: None,
            attempts: 3,
        }
    }

    fn detect_patterns<'a>(haystack: &str, patterns: &[&'a str]) -> Vec<&'a str> {
        patterns
            .iter()
            .copied()
            .filter(|p| haystack.contains(p))
            .collect()
    }
}

/// Implementation of the Default trait for the ShellDetector plugin.
impl Default for ShellDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the ShellDetector plugin.
impl Plugin for ShellDetector {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Detect interactive shell or login prompt on a UART interface",
            description: "Connects at the configured baud rate, sends newlines to wake the \
                          device and checks the response for shell/login prompt patterns. \
                          Flags unauthenticated root shells as critical findings.",
            needs_root: false,
            args: &[
                CliArg { name: "port", short: Some('p'), help: "Serial port (e.g., /dev/ttyUSB0)", value_name: "PATH", default: None, is_flag: false },
                CliArg { name: "baud_rate", short: Some('b'), help: "Baud rate", value_name: "BAUD", default: Some("115200"), is_flag: false },
                CliArg { name: "attempts", short: None, help: "Number of stimulus attempts", value_name: "N", default: Some("3"), is_flag: false },
                CliArg { name: "timeout_ms", short: None, help: "Read timeout per attempt (ms)", value_name: "MS", default: Some("500"), is_flag: false },
            ],
        )
    }

    /// Initialize the shell detector with the given plugin configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = UartConfig::from_plugin_config(config)?;
        self.attempts = config.parse_or("attempts", 3u8);
        self.connect()
    }

    /// Execute the shell detection process and report findings.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        let mut all_output = String::new();

        for attempt in 0..self.attempts {
            tracing::debug!(attempt, "sending stimulus");
            if let Some(s) = self.session_mut() {
                let _ = s.write_bytes(b"\r\n");
                let _ = s.flush();
            }

            // Give the device a moment to respond (one full timeout cycle).
            let raw = self
                .session_mut()
                .map(|s| s.drain())
                .transpose()?
                .unwrap_or_default();

            let chunk = String::from_utf8_lossy(&raw).into_owned();
            if !chunk.is_empty() {
                tracing::debug!(attempt, bytes = raw.len(), "received output");
            }
            all_output.push_str(&chunk);
        }

        if all_output.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No response received",
                format!(
                    "No output at {} baud after {} attempts.",
                    self.config.baud_rate, self.attempts
                ),
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        // Boot messages: informational, device is alive.
        let boot_hits = Self::detect_patterns(&all_output, BOOT_PATTERNS);
        if !boot_hits.is_empty() {
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    "Boot messages detected",
                    format!("Device is booting (matched: {}).", boot_hits.join(", ")),
                )
                .with_evidence(all_output.chars().take(200).collect::<String>()),
            );
        }

        let shell_hits = Self::detect_patterns(&all_output, SHELL_PATTERNS);

        if shell_hits.is_empty() {
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    "No shell/login prompt detected",
                    "Device responded but no recognized shell or login prompt was found.",
                )
                .with_evidence(all_output.chars().take(200).collect::<String>()),
            );
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        // Distinguish unauthenticated root shells from login prompts.
        let is_unauth_root = shell_hits.iter().any(|&p| matches!(p, "# " | "root@"));
        let is_login = shell_hits
            .iter()
            .any(|&p| matches!(p, "login:" | "Login:" | "Password:" | "password:"));

        if is_unauth_root {
            result.add(
                PluginFinding::new(
                    Severity::Critical,
                    "Unauthenticated root shell on UART",
                    format!(
                        "A root shell is directly accessible on {} at {} baud \
                         with no authentication required.",
                        self.config.port, self.config.baud_rate
                    ),
                )
                .with_evidence(all_output.chars().take(400).collect::<String>()),
            );
        } else if is_login {
            result.add(
                PluginFinding::new(
                    Severity::High,
                    "Login prompt exposed on UART",
                    format!(
                        "A login prompt is accessible on {} at {} baud. \
                         Default or weak credentials should be tested.",
                        self.config.port, self.config.baud_rate
                    ),
                )
                .with_evidence(all_output.chars().take(400).collect::<String>()),
            );
        } else {
            result.add(
                PluginFinding::new(
                    Severity::Medium,
                    "Interactive prompt detected on UART",
                    format!(
                        "An interactive prompt was found on {} at {} baud (matched: {}).",
                        self.config.port,
                        self.config.baud_rate,
                        shell_hits.join(", ")
                    ),
                )
                .with_evidence(all_output.chars().take(400).collect::<String>()),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }

    fn teardown(&mut self) -> Result<()> {
        self.disconnect();
        Ok(())
    }
}

/// SerialPlugin implementation for the ShellDetector plugin.
impl SerialPlugin for ShellDetector {
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
    crate::PluginFactory(|| Box::new(ShellDetector::new()) as Box<dyn crate::Plugin>)
}
