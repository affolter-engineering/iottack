use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

const IAC: u8 = 0xFF;
const WILL: u8 = 0xFB;
const WONT: u8 = 0xFC;
const DO: u8 = 0xFD;
const DONT: u8 = 0xFE;

/// Patterns that indicate a login prompt.
const LOGIN_PATTERNS: &[&str] = &[
    "login:",
    "Login:",
    "username:",
    "Username:",
    "Password:",
    "password:",
    "root@",
    "admin@",
    "BusyBox",
    "busybox",
    "U-Boot",
    "bash",
    "sh-",
];

/// Patterns that indicate an already-open shell (checked at line-start only).
const SHELL_PATTERNS: &[&str] = &["# ", "$ "];

/// Common default credentials found on IoT devices.
const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("admin", "password"),
    ("admin", "1234"),
    ("user", "user"),
    ("guest", "guest"),
];

/// Telnet scanner structure.
pub struct TelnetScanner {
    host: String,
    port: u16,
    timeout_ms: u64,
    try_creds: bool,
}

/// Implementation of the Telnet scanner.
impl TelnetScanner {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 23,
            timeout_ms: 3_000,
            try_creds: false,
        }
    }

    /// Strip IAC option negotiation bytes and respond to each command.
    fn negotiate(stream: &mut TcpStream, raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == IAC && i + 2 < raw.len() {
                let cmd = raw[i + 1];
                let opt = raw[i + 2];
                let reply = match cmd {
                    WILL => Some([IAC, DONT, opt]),
                    DO => Some([IAC, WONT, opt]),
                    _ => None,
                };
                if let Some(r) = reply {
                    let _ = stream.write_all(&r);
                }
                i += 3;
            } else if raw[i] == IAC && i + 1 < raw.len() {
                i += 2;
            } else {
                out.push(raw[i]);
                i += 1;
            }
        }
        out
    }

    /// Read raw bytes from the stream up to the specified limit.
    fn read_bytes(stream: &mut TcpStream, limit: usize) -> Vec<u8> {
        let mut buf = vec![0u8; limit];
        match stream.read(&mut buf) {
            Ok(n) => buf[..n].to_vec(),
            Err(_) => Vec::new(),
        }
    }

    /// Send a line to the stream and receive the response.
    fn send_recv(stream: &mut TcpStream, line: &str) -> Vec<u8> {
        let _ = stream.write_all(line.as_bytes());
        let _ = stream.flush();
        Self::read_bytes(stream, 1024)
    }

    /// Check if the given text contains a shell prompt.
    fn has_shell_prompt(text: &str) -> bool {
        text.contains("root@")
            || text.lines().any(|l| {
                let t = l.trim_start();
                SHELL_PATTERNS.iter().any(|p| t.starts_with(p))
            })
    }
}

/// Default implementation for the TelnetScanner.
impl Default for TelnetScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin implementation for the TelnetScanner.
impl Plugin for TelnetScanner {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Connect to a Telnet service and detect banners, login prompts and default credentials",
            description: "Opens a TCP connection to the target Telnet port, captures the banner, \
                          strips IAC negotiation bytes, and checks for shell/login prompt patterns. \
                          Optionally probes common default credentials. \
                          Flags Telnet exposure as High severity due to cleartext transmission.",
            needs_root: false,
            args: &[
                CliArg { name: "host", short: Some('H'), help: "Target host (IP or hostname)", value_name: "HOST", default: None, is_flag: false },
                CliArg { name: "port", short: Some('p'), help: "Target port", value_name: "PORT", default: Some("23"), is_flag: false },
                CliArg { name: "timeout_ms", short: None, help: "Connection/read timeout (ms)", value_name: "MS", default: Some("3000"), is_flag: false },
                CliArg { name: "try_creds",  short: None, help: "Probe common default credentials", value_name: "", default: None, is_flag: true  },
            ],
        )
    }

    /// Initialize the Telnet scanner with the given configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.require("host")?.to_string();
        self.port = config.parse_or("port", 23u16);
        self.timeout_ms = config.parse_or("timeout_ms", 3_000u64);
        self.try_creds = config.get_or("try_creds", "false") == "true";
        Ok(())
    }

    /// Execute the Telnet scan against the configured target.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        let addr = format!("{}:{}", self.host, self.port);
        let timeout = Duration::from_millis(self.timeout_ms);

        let sock_addr = addr
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("could not resolve {addr}: {e}"))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("no addresses found for {addr}"))?;

        let mut stream = match TcpStream::connect_timeout(&sock_addr, timeout) {
            Ok(s) => s,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Telnet port not reachable",
                    format!("Could not connect to {addr}: {e}"),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        result.add(PluginFinding::new(
            Severity::High,
            format!("Telnet service open on {addr}"),
            "Telnet transmits credentials and data in cleartext. \
             Replace with SSH wherever possible.",
        ));

        let raw = Self::read_bytes(&mut stream, 2048);
        let clean = Self::negotiate(&mut stream, &raw);
        let banner = String::from_utf8_lossy(&clean)
            .chars()
            .filter(|c| c.is_ascii_graphic() || matches!(c, ' ' | '\t' | '\r' | '\n'))
            .collect::<String>()
            .trim()
            .to_string();

        if !banner.is_empty() {
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    "Telnet banner",
                    format!("Banner received from {addr}."),
                )
                .with_evidence(banner.chars().take(400).collect::<String>()),
            );
        }

        // Check for an unauthenticated shell before looking for login prompts.
        if Self::has_shell_prompt(&banner) {
            result.add(PluginFinding::new(
                Severity::Critical,
                "Unauthenticated shell on Telnet",
                format!(
                    "A root/shell prompt is directly accessible on {addr} with no login required."
                ),
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        let has_login = LOGIN_PATTERNS.iter().any(|p| banner.contains(p));

        if !has_login {
            // Poke with a newline and check again.
            let raw2 = Self::send_recv(&mut stream, "\r\n");
            let clean2 = Self::negotiate(&mut stream, &raw2);
            let banner2 = String::from_utf8_lossy(&clean2).into_owned();
            if LOGIN_PATTERNS.iter().any(|p| banner2.contains(p)) {
                result.add(PluginFinding::new(
                    Severity::Medium,
                    "Login prompt detected after stimulus",
                    format!("A prompt appeared on {addr} after sending a newline."),
                ));
            } else {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "No login prompt detected",
                    format!("No recognisable shell or login prompt found on {addr}."),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        } else {
            result.add(PluginFinding::new(
                Severity::Medium,
                "Login prompt detected",
                format!("A login prompt is accessible on {addr}. Test default credentials."),
            ));
        }

        if self.try_creds {
            for &(user, pass) in DEFAULT_CREDS {
                let after_user = Self::send_recv(&mut stream, &format!("{user}\r\n"));
                let after_pass = Self::send_recv(&mut stream, &format!("{pass}\r\n"));
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&after_user),
                    String::from_utf8_lossy(&after_pass),
                );
                let is_denied = combined.to_lowercase().contains("incorrect")
                    || combined.to_lowercase().contains("failed")
                    || combined.to_lowercase().contains("invalid")
                    || combined.to_lowercase().contains("denied");

                if Self::has_shell_prompt(&combined) && !is_denied {
                    let cred_str = if pass.is_empty() {
                        format!("{user}/(empty)")
                    } else {
                        format!("{user}/{pass}")
                    };
                    result.add(
                        PluginFinding::new(
                            Severity::Critical,
                            format!("Default credentials accepted: {cred_str}"),
                            format!(
                                "Telnet on {addr} accepted {cred_str} and returned a shell prompt."
                            ),
                        )
                        .with_evidence(combined.chars().take(200).collect::<String>()),
                    );
                    // Reconnect for the next attempt.
                    match TcpStream::connect_timeout(&sock_addr, timeout) {
                        Ok(s) => {
                            stream = s;
                            let _ = stream.set_read_timeout(Some(timeout));
                            let _ = stream.set_write_timeout(Some(timeout));
                            let _ = Self::read_bytes(&mut stream, 1024);
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(TelnetScanner::new()) as Box<dyn crate::Plugin>)
}
