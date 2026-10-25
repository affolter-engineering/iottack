use super::payloads::{
    FuzzPayload, INTERESTING_PATTERNS, OwnedFuzzPayload, PAYLOADS, charset_payloads,
    named_payload_set, wordlist_payloads,
};
use crate::core::{PluginFinding, Severity};
use anyhow::Result;
use std::time::Duration;

/// A transport that the fuzzing engine sends payloads through and reads
/// responses from. Implement this for each protocol (UART, TCP, etc.).
pub trait FuzzTransport {
    /// Send `payload` and return any response bytes received.
    fn send_recv(&mut self, payload: &[u8]) -> Result<Vec<u8>>;
}

/// One interesting response: which payload triggered it, what patterns matched,
/// a short preview of the response, and the derived severity.
pub struct FuzzMatch {
    pub payload_label: String,
    pub matched_patterns: Vec<String>,
    pub response_preview: String,
    pub severity: Severity,
}

/// Runs a set of payloads through a [`FuzzTransport`] and returns all
/// responses that matched at least one interesting pattern.
pub struct FuzzEngine {
    payloads: &'static [FuzzPayload],
    extra_payloads: Vec<OwnedFuzzPayload>,
    patterns: &'static [&'static str],
    extra_patterns: Vec<String>,
    suffix: Vec<u8>,
    iterations: u32,
    delay: Duration,
}

/// Parse escape sequences in a string (`\r`, `\n`, `\t`, `\0`, `\\`).
impl FuzzEngine {
    pub fn new(iterations: u32) -> Self {
        Self {
            payloads: PAYLOADS,
            extra_payloads: Vec::new(),
            patterns: INTERESTING_PATTERNS,
            extra_patterns: Vec::new(),
            suffix: Vec::new(),
            iterations,
            delay: Duration::ZERO,
        }
    }

    /// Set a delay between each payload. Default is no delay.
    pub fn with_delay_ms(mut self, ms: u64) -> Self {
        self.delay = Duration::from_millis(ms);
        self
    }

    /// Append `suffix` bytes to every payload before sending.
    ///
    /// Recognizes `\r`, `\n`, `\t`, `\0`, `\\` escape sequences in the string.
    pub fn with_suffix(mut self, s: &str) -> Self {
        self.suffix = parse_escapes(s);
        self
    }

    /// Add extra response patterns to match in addition to the built-in set.
    pub fn with_extra_patterns(mut self, patterns: &[&str]) -> Self {
        self.extra_patterns
            .extend(patterns.iter().map(|s| s.to_string()));
        self
    }

    /// Override the default payload set.
    pub fn with_payloads(mut self, payloads: &'static [FuzzPayload]) -> Self {
        self.payloads = payloads;
        self
    }

    /// Override the default pattern set.
    pub fn with_patterns(mut self, patterns: &'static [&'static str]) -> Self {
        self.patterns = patterns;
        self
    }

    /// Add one payload per (character, length) combination from `charset`, up to `max_length`.
    pub fn with_charset(mut self, charset: &str, max_length: usize) -> Self {
        if !charset.is_empty() && max_length > 0 {
            self.extra_payloads
                .extend(charset_payloads(charset, max_length));
        }
        self
    }

    /// Load payloads from a wordlist file (one entry per line).
    pub fn with_wordlist(mut self, path: &str) -> Result<Self> {
        self.extra_payloads.extend(wordlist_payloads(path)?);
        Ok(self)
    }

    /// Add a pre-built owned payload.
    pub fn with_payload(mut self, payload: OwnedFuzzPayload) -> Self {
        self.extra_payloads.push(payload);
        self
    }

    /// Add payloads from one or more named sets (comma-separated).
    ///
    /// Available sets: `digits`, `lowercase`, `uppercase`, `ascii`
    /// Example: `"digits,uppercase"` adds both sets.
    pub fn with_payload_sets(mut self, sets: &str) -> anyhow::Result<Self> {
        for name in sets.split(',') {
            let name = name.trim();
            if !name.is_empty() {
                self.extra_payloads.extend(named_payload_set(name)?);
            }
        }
        Ok(self)
    }

    /// Run all payloads × iterations through `transport`.
    pub fn run(&self, transport: &mut dyn FuzzTransport) -> Result<Vec<FuzzMatch>> {
        let mut matches = Vec::new();

        let all: Vec<(&str, &[u8])> = self
            .payloads
            .iter()
            .map(|p| (p.label, p.data))
            .chain(
                self.extra_payloads
                    .iter()
                    .map(|p| (p.label.as_str(), p.data.as_slice())),
            )
            .collect();

        for iteration in 0..self.iterations {
            for (i, &(label, data)) in all.iter().enumerate() {
                let wire = if self.suffix.is_empty() {
                    data.to_vec()
                } else {
                    [data, self.suffix.as_slice()].concat()
                };

                let wire_str: String = wire
                    .iter()
                    .flat_map(|b| b.escape_ascii())
                    .map(char::from)
                    .collect();
                tracing::debug!(
                    iteration,
                    label,
                    bytes = wire.len(),
                    payload = wire_str,
                    "sending payload"
                );

                let raw = transport.send_recv(&wire)?;

                if !self.delay.is_zero() && i + 1 < all.len() {
                    std::thread::sleep(self.delay);
                }

                if raw.is_empty() {
                    continue;
                }

                let text = String::from_utf8_lossy(&raw);
                let matched: Vec<String> = self
                    .patterns
                    .iter()
                    .map(|s| *s)
                    .chain(self.extra_patterns.iter().map(String::as_str))
                    .filter(|p| text.contains(p))
                    .map(|s| s.to_string())
                    .collect();

                if matched.is_empty() {
                    continue;
                }

                tracing::info!(label, ?matched, "interesting response");

                let severity = Self::classify(&matched);
                let preview = text
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || matches!(c, ' ' | '\n'))
                    .take(200)
                    .collect();

                matches.push(FuzzMatch {
                    payload_label: label.to_string(),
                    matched_patterns: matched,
                    response_preview: preview,
                    severity,
                });
            }
        }

        Ok(matches)
    }

    /// Convert a list of `FuzzMatch` results into `PluginFinding` values.
    pub fn to_findings(matches: &[FuzzMatch], context: &str) -> Vec<PluginFinding> {
        matches
            .iter()
            .map(|m| {
                PluginFinding::new(
                    m.severity.clone(),
                    format!("Interesting response to '{}' payload", m.payload_label),
                    format!(
                        "{} responded with patterns [{}] after receiving the '{}' payload.",
                        context,
                        m.matched_patterns.join(", "),
                        m.payload_label,
                    ),
                )
                .with_evidence(m.response_preview.clone())
            })
            .collect()
    }

    fn classify(matched: &[String]) -> Severity {
        if matched.iter().any(|p| {
            matches!(
                p.as_str(),
                "fault"
                    | "Fault"
                    | "panic"
                    | "exception"
                    | "Exception"
                    | "stack"
                    | "crash"
                    | "abort"
                    | "segfault"
                    | "overflow"
            )
        }) {
            Severity::Critical
        } else if matched
            .iter()
            .any(|p| matches!(p.as_str(), "root@" | "# " | "$ " | "login:" | "password:"))
        {
            Severity::High
        } else {
            Severity::Medium
        }
    }
}

/// Parse common escape sequences (`\r`, `\n`, `\t`, `\0`, `\\`) in `s`.
pub fn parse_escapes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('r') => out.push(b'\r'),
                Some('n') => out.push(b'\n'),
                Some('t') => out.push(b'\t'),
                Some('0') => out.push(b'\0'),
                Some('\\') => out.push(b'\\'),
                Some(other) => {
                    out.push(b'\\');
                    out.extend_from_slice(other.to_string().as_bytes());
                }
                None => out.push(b'\\'),
            }
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}
