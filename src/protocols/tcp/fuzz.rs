use super::{TcpConfig, TcpPlugin, TcpSession, DEFAULT_TIMEOUT_MS};
use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::fuzzing::{FuzzEngine, FuzzTransport};
use crate::plugin_meta;
use anyhow::Result;
use std::io::{ErrorKind, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// TCP transport for the fuzzing engine. Wraps a TCP session and manages connection behavior.
struct TcpTransport<'a> {
    session:   &'a mut TcpSession,
    /// When true, a fresh connection is opened for every payload.
    reconnect: bool,
    config:    TcpConfig,
}

/// TCP transport implementation for the fuzzing engine. Handles sending and receiving payloads over TCP.
impl FuzzTransport for TcpTransport<'_> {
    fn send_recv(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.reconnect {
            self.session.stream = open_stream(&self.config)?;
            // Discard any banner the server sends on connect.
            let _ = self.session.drain();
        }

        self.session.write_bytes(payload)?;
        self.session.flush()?;

        match self.session.drain() {
            Ok(data) => Ok(data),
            // Connection reset / EOF after a payload — not unusual; return empty response.
            Err(e) if matches!(
                e.downcast_ref::<std::io::Error>().map(|e| e.kind()),
                Some(ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe)
            ) => {
                tracing::debug!("connection closed by peer after payload");
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }
}

/// Open a TCP stream to the target specified in the configuration, applying the configured timeout.
fn open_stream(config: &TcpConfig) -> Result<TcpStream> {
    let timeout = Duration::from_millis(config.timeout_ms);
    let sock = config
        .addr()
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for {}", config.addr()))?;
    let stream = TcpStream::connect_timeout(&sock, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Fuzzer for TCP services. Manages configuration, session state, and fuzzing parameters.
pub struct TcpFuzzer {
    config:       TcpConfig,
    session:      Option<TcpSession>,
    reconnect:    bool,
    iterations:   u32,
    charset:      Option<String>,
    length:       usize,
    wordlist:     Option<String>,
    delay_ms:     u64,
    suffix:       String,
    patterns:     Vec<String>,
    payload_sets: Option<String>,
}

/// Constructor and initializer for the TCP fuzzer. Sets default values for all fuzzing parameters.
impl TcpFuzzer {
    pub fn new() -> Self {
        Self {
            config:       TcpConfig::default(),
            session:      None,
            reconnect:    false,
            iterations:   1,
            charset:      None,
            length:       16,
            wordlist:     None,
            delay_ms:     0,
            suffix:       String::new(),
            patterns:     Vec::new(),
            payload_sets: None,
        }
    }
}

/// Default implementation for the TCP fuzzer. Delegates to the `new` constructor.
impl Default for TcpFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the `Plugin` trait for the TCP fuzzer. Provides metadata and argument definitions.
impl Plugin for TcpFuzzer {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Send malformed payloads to a TCP service and report anomalous responses",
            description: "Connects to the target TCP host:port and iterates a set of fuzzing \
                          payloads (null bytes, long strings, format strings, shell metacharacters, \
                          boundary values, control characters). Each response is checked for error \
                          messages, crash indicators and unexpected shell or login prompts. \
                          Supports charset-based Cartesian-product generation, wordlist files and \
                          named payload sets (digits, lowercase, uppercase, ascii). \
                          Use --reconnect to open a fresh connection for every payload.",
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
                    name: "reconnect",
                    short: Some('r'),
                    help: "Open a new connection for every payload",
                    value_name: "",
                    default: None,
                    is_flag: true
                },
                CliArg {
                    name: "iterations",
                    short: None,
                    help: "Times to repeat the payload set",
                    value_name: "N",
                    default: Some("1"),
                    is_flag: false
                },
                CliArg {
                    name: "charset",
                    short: Some('c'),
                    help: "Chars to fuzz (Cartesian product up to --length)",
                    value_name: "CHARS",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "length",
                    short: Some('l'),
                    help: "Max repeat length for charset payloads",
                    value_name: "N",
                    default: Some("16"),
                    is_flag: false
                },
                CliArg {
                    name: "wordlist",
                    short: Some('w'),
                    help: "Wordlist file, one payload per line (replaces built-ins)",
                    value_name: "PATH",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "suffix",
                    short: Some('s'),
                    help: r"Bytes appended to every payload, e.g., '\r\n'",
                    value_name: "BYTES",
                    default: Some(""),
                    is_flag: false
                },
                CliArg {
                    name: "pattern",
                    short: None,
                    help: "Extra response pattern to flag (repeatable)",
                    value_name: "STRING",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "delay_ms",
                    short: Some('d'),
                    help: "Delay between payloads in milliseconds",
                    value_name: "MS",
                    default: Some("0"),
                    is_flag: false
                },
                CliArg {
                    name: "payload-set",
                    short: None,
                    help: "Named sets to add: digits, lowercase, uppercase, ascii",
                    value_name: "SETS",
                    default: None,
                    is_flag: false
                },
            ],
        )
    }

    /// Initialize the TCP fuzzer with the provided plugin configuration. Parses all relevant arguments and establishes the initial connection.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config     = TcpConfig::from_plugin_config(config)?;
        self.reconnect  = config.get("reconnect") == Some("true");
        self.iterations = config.parse_or("iterations", 1u32);
        self.charset    = config.get("charset").map(|s| s.to_string());
        self.length     = config.parse_or("length", 16usize);
        self.wordlist   = config.get("wordlist").map(|s| s.to_string());
        self.suffix     = config.get_or("suffix", "").to_string();
        self.delay_ms   = config.parse_or("delay_ms", 0u64);
        if let Some(p) = config.get("pattern") {
            self.patterns.push(p.to_string());
        }
        self.payload_sets = config.get("payload-set").map(|s| s.to_string());
        self.connect()
    }

    /// Execute the fuzzing process. Runs the fuzzing engine against the target and collects findings.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        let addr = self.config.addr();

        // Discard any banner the server sends on connect.
        if let Some(s) = self.session_mut() {
            let _ = s.drain();
        }

        let extra: Vec<&str> = self.patterns.iter().map(String::as_str).collect();
        let mut engine = FuzzEngine::new(self.iterations)
            .with_delay_ms(self.delay_ms)
            .with_suffix(&self.suffix)
            .with_extra_patterns(&extra);

        if self.wordlist.is_some() || self.charset.is_some() || self.payload_sets.is_some() {
            engine = engine.with_payloads(&[]);
        }
        if let Some(ref path) = self.wordlist {
            engine = engine.with_wordlist(path)?;
        }
        if let Some(ref charset) = self.charset {
            engine = engine.with_charset(charset, self.length);
        }
        if let Some(ref sets) = self.payload_sets {
            engine = engine.with_payload_sets(sets)?;
        }

        let reconnect = self.reconnect;
        let config    = self.config.clone();

        let matches = if let Some(session) = self.session_mut() {
            let mut transport = TcpTransport { session, reconnect, config };
            engine.run(&mut transport)?
        } else {
            Vec::new()
        };

        if matches.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No interesting responses",
                format!(
                    "All payloads × {} iteration(s) produced no interesting output on {}.",
                    self.iterations, addr,
                ),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            for finding in FuzzEngine::to_findings(&matches, &addr) {
                result.add(finding);
            }
            let security_issue = matches
                .iter()
                .any(|m| matches!(m.severity, Severity::Critical | Severity::High));
            result.finish(if security_issue { PluginStatus::Fail } else { PluginStatus::Pass });
        }

        Ok(result)
    }

    fn teardown(&mut self) -> Result<()> {
        self.disconnect();
        Ok(())
    }
}

/// Implementation of the `TcpPlugin` trait for the TCP fuzzer. Provides access to the TCP configuration and session management functions.
impl TcpPlugin for TcpFuzzer {
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
    crate::PluginFactory(|| Box::new(TcpFuzzer::new()) as Box<dyn crate::Plugin>)
}
