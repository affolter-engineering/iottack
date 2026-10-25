use super::{SerialPlugin, UartConfig, UartSession};
use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::fuzzing::{FuzzEngine, FuzzTransport};
use crate::plugin_meta;
use anyhow::Result;

struct UartTransport<'a> {
    session: &'a mut UartSession,
}

impl FuzzTransport for UartTransport<'_> {
    fn send_recv(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.session.write_bytes(payload)?;
        self.session.flush()?;
        self.session.drain()
    }
}

pub struct UartFuzzer {
    config: UartConfig,
    session: Option<UartSession>,
    iterations: u32,
    charset: Option<String>,
    length: usize,
    wordlist: Option<String>,
    delay_ms: u64,
    suffix: String,
    patterns: Vec<String>,
    payload_sets: Option<String>,
}

impl UartFuzzer {
    pub fn new() -> Self {
        Self {
            config: UartConfig::default(),
            session: None,
            iterations: 1,
            charset: None,
            length: 64,
            wordlist: None,
            delay_ms: 0,
            suffix: String::new(),
            patterns: Vec::new(),
            payload_sets: None,
        }
    }
}

impl Default for UartFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for UartFuzzer {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Send malformed payloads to a UART interface and report anomalous responses",
            description: "Iterates a set of fuzzing payloads (null bytes, long strings, format \
                          strings, shell metacharacters, boundary values, control characters, etc.) \
                          and checks each response for error messages, crash indicators, or \
                          unexpected shell/login prompts.",
            needs_root: false,
            args: &[
                CliArg { name: "port",       short: Some('p'), help: "Serial port (e.g. /dev/ttyUSB0)",                      value_name: "PATH",    default: None,           is_flag: false },
                CliArg { name: "baud_rate",  short: Some('b'), help: "Baud rate",                                            value_name: "BAUD",    default: Some("115200"), is_flag: false },
                CliArg { name: "timeout_ms", short: None,      help: "Read timeout per payload (ms)",                        value_name: "MS",      default: Some("500"),    is_flag: false },
                CliArg { name: "iterations", short: None,      help: "Times to repeat the payload set",                      value_name: "N",       default: Some("1"),      is_flag: false },
                CliArg { name: "charset",    short: Some('c'), help: "Chars to fuzz (one payload per char x length)",        value_name: "CHARS",   default: None,           is_flag: false },
                CliArg { name: "length",     short: Some('l'), help: "Max repeat length for charset payloads",               value_name: "N",       default: Some("16"),     is_flag: false },
                CliArg { name: "wordlist",   short: Some('w'), help: "Wordlist file (replaces built-in payloads)",           value_name: "PATH",    default: None,           is_flag: false },
                CliArg { name: "suffix",     short: Some('s'), help: r"Bytes appended to every payload, e.g. '\r\n'",        value_name: "BYTES",   default: Some(""),       is_flag: false },
                CliArg { name: "pattern",    short: None,      help: "Extra response pattern to flag (repeatable via key=v)", value_name: "STRING",  default: None,           is_flag: false },
                CliArg { name: "delay_ms",    short: Some('d'), help: "Delay between payloads in milliseconds",                                        value_name: "MS",      default: Some("0"),  is_flag: false },
                CliArg { name: "payload-set", short: None,      help: "Named payload sets to add, comma-separated (digits,lowercase,uppercase,ascii)", value_name: "SETS",    default: None,       is_flag: false },
            ],
        )
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = UartConfig::from_plugin_config(config)?;
        self.iterations = config.parse_or("iterations", 1u32);
        self.charset = config.get("charset").map(|s| s.to_string());
        self.length = config.parse_or("length", 64usize);
        self.wordlist = config.get("wordlist").map(|s| s.to_string());
        self.suffix = config.get("suffix").unwrap_or("").to_string();
        self.delay_ms = config.parse_or("delay_ms", 0u64);
        if let Some(p) = config.get("pattern") {
            self.patterns.push(p.to_string());
        }
        self.payload_sets = config.get("payload-set").map(|s| s.to_string());
        self.connect()
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let extra: Vec<&str> = self.patterns.iter().map(String::as_str).collect();
        let mut engine = FuzzEngine::new(self.iterations)
            .with_delay_ms(self.delay_ms)
            .with_suffix(&self.suffix)
            .with_extra_patterns(&extra);

        if self.wordlist.is_some() || self.charset.is_some() {
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

        let matches = if let Some(session) = self.session_mut() {
            let mut transport = UartTransport { session };
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
                    self.iterations, self.config.port,
                ),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            for finding in FuzzEngine::to_findings(&matches, &self.config.port) {
                result.add(finding);
            }
            let security_issue = matches
                .iter()
                .any(|m| matches!(m.severity, Severity::Critical | Severity::High));
            if security_issue {
                result.finish(PluginStatus::Fail);
            } else {
                result.finish(PluginStatus::Pass);
            }
        }

        Ok(result)
    }

    fn teardown(&mut self) -> Result<()> {
        self.disconnect();
        Ok(())
    }
}

impl SerialPlugin for UartFuzzer {
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
    crate::PluginFactory(|| Box::new(UartFuzzer::new()) as Box<dyn crate::Plugin>)
}
