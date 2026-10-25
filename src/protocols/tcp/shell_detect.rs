use super::{DEFAULT_TIMEOUT_MS, TcpConfig, TcpPlugin, TcpSession};
use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;

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

const BOOT_PATTERNS: &[&str] = &[
    "Booting", "booting", "Starting", "Loading", "Kernel", "U-Boot", "GRUB", "init:", "systemd",
];

pub struct TcpShellDetector {
    config: TcpConfig,
    session: Option<TcpSession>,
    attempts: u8,
    stimulus: String,
}

impl TcpShellDetector {
    pub fn new() -> Self {
        Self {
            config: TcpConfig::default(),
            session: None,
            attempts: 3,
            stimulus: "\r\n".to_string(),
        }
    }

    fn detect<'a>(haystack: &str, patterns: &[&'a str]) -> Vec<&'a str> {
        patterns
            .iter()
            .copied()
            .filter(|p| haystack.contains(p))
            .collect()
    }
}

impl Default for TcpShellDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for TcpShellDetector {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Detect interactive shell or login prompt on a TCP service",
            description: "Connects to the target host:port, reads the initial banner, then sends \
                          a configurable stimulus (default: CRLF) up to --attempts times and \
                          checks all received output for shell and login prompt patterns. \
                          Unauthenticated root shells are Critical; login prompts are High.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "host",
                    short: Some('H'),
                    help: "Target hostname or IP address",
                    value_name: "HOST",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "port",
                    short: Some('p'),
                    help: "Target TCP port",
                    value_name: "PORT",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "timeout_ms",
                    short: None,
                    help: "Connect and read timeout (ms)",
                    value_name: "MS",
                    default: Some("3000"),
                    is_flag: false
                },
                CliArg {
                    name: "attempts",
                    short: None,
                    help: "Number of stimulus attempts after the initial banner",
                    value_name: "N",
                    default: Some("3"),
                    is_flag: false
                },
                CliArg {
                    name: "stimulus",
                    short: Some('S'),
                    help: r"Bytes to send as stimulus, e.g., '\r\n' or 'help\r\n'",
                    value_name: "BYTES",
                    default: Some(r"\r\n"),
                    is_flag: false
                },
            ],
        )
    }

    /// Initialize the plugin with the given configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = TcpConfig::from_plugin_config(config)?;
        self.attempts = config.parse_or("attempts", 3u8);
        self.stimulus = config.get_or("stimulus", r"\r\n").to_string();
        self.connect()
    }

    /// Execute the plugin logic and return the result.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        let addr = self.config.addr();
        let stimulus = crate::fuzzing::parse_escapes(&self.stimulus);

        let mut all_output = String::new();

        // Read the initial banner.
        if let Some(s) = self.session_mut() {
            match s.drain() {
                Ok(raw) => {
                    let chunk = String::from_utf8_lossy(&raw).into_owned();
                    tracing::debug!(bytes = raw.len(), "initial banner");
                    all_output.push_str(&chunk);
                }
                Err(e) => tracing::debug!("banner read error: {e}"),
            }
        }

        // Send stimulus and collect responses.
        for attempt in 0..self.attempts {
            tracing::debug!(attempt, "sending stimulus");
            if let Some(s) = self.session_mut() {
                let _ = s.write_bytes(&stimulus);
                let _ = s.flush();
                match s.drain() {
                    Ok(raw) if !raw.is_empty() => {
                        tracing::debug!(attempt, bytes = raw.len(), "received output");
                        all_output.push_str(&String::from_utf8_lossy(&raw));
                    }
                    _ => {}
                }
            }
        }

        if all_output.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No response received",
                format!(
                    "No output from {addr} after banner read + {} stimulus attempt(s).",
                    self.attempts
                ),
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        let boot_hits = Self::detect(&all_output, BOOT_PATTERNS);
        if !boot_hits.is_empty() {
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    "Boot messages detected",
                    format!(
                        "Device appears to be booting (matched: {}).",
                        boot_hits.join(", ")
                    ),
                )
                .with_evidence(all_output.chars().take(200).collect::<String>()),
            );
        }

        let shell_hits = Self::detect(&all_output, SHELL_PATTERNS);

        if shell_hits.is_empty() {
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    "No shell or login prompt detected",
                    format!("{addr} responded but no recognized prompt was found."),
                )
                .with_evidence(all_output.chars().take(200).collect::<String>()),
            );
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        let is_unauth_root = shell_hits.iter().any(|&p| matches!(p, "# " | "root@"));
        let is_login = shell_hits
            .iter()
            .any(|&p| matches!(p, "login:" | "Login:" | "Password:" | "password:"));

        if is_unauth_root {
            result.add(
                PluginFinding::new(
                    Severity::Critical,
                    format!("Unauthenticated root shell on {addr}"),
                    format!("A root shell is directly accessible on {addr} with no authentication required."),
                )
                .with_evidence(all_output.chars().take(400).collect::<String>()),
            );
        } else if is_login {
            result.add(
                PluginFinding::new(
                    Severity::High,
                    format!("Login prompt exposed on {addr}"),
                    format!("A login prompt is accessible on {addr}. Test default credentials with 'iottack network telnet --try-creds'."),
                )
                .with_evidence(all_output.chars().take(400).collect::<String>()),
            );
        } else {
            result.add(
                PluginFinding::new(
                    Severity::Medium,
                    format!("Interactive prompt on {addr}"),
                    format!(
                        "An interactive prompt was found on {addr} (matched: {}).",
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

impl TcpPlugin for TcpShellDetector {
    fn tcp_config(&self) -> &TcpConfig {
        &self.config
    }
    fn session(&self) -> Option<&TcpSession> {
        self.session.as_ref()
    }
    fn session_mut(&mut self) -> Option<&mut TcpSession> {
        self.session.as_mut()
    }
    fn set_session(&mut self, s: Option<TcpSession>) {
        self.session = s;
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(TcpShellDetector::new()) as Box<dyn crate::Plugin>)
}
