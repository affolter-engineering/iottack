use anyhow::Result;
use std::fs;

/// A named fuzzing payload backed by static data.
pub struct FuzzPayload {
    pub label: &'static str,
    pub data:  &'static [u8],
}

/// A named fuzzing payload with owned data, used for runtime-generated payloads.
pub struct OwnedFuzzPayload {
    pub label: String,
    pub data:  Vec<u8>,
}

impl OwnedFuzzPayload {
    /// Build a payload of `byte` repeated `length` times.
    pub fn repeated(byte: u8, length: usize) -> Self {
        Self {
            label: format!("'{}' x {length}", byte.escape_ascii()),
            data:  vec![byte; length],
        }
    }
}

/// Generate one payload per (character, length) combination.
///
/// Iterates length from 1 to `max_length`; for each length emits every byte in
/// `charset`. For charset `"ab"` and max_length `3` this yields:
/// `'a'x1`, `'b'x1`, `'a'x2`, `'b'x2`, `'a'x3`, `'b'x3`.
pub fn charset_payloads(charset: &str, max_length: usize) -> Vec<OwnedFuzzPayload> {
    let mut out = Vec::new();
    for length in 1..=max_length {
        for byte in charset.bytes() {
            out.push(OwnedFuzzPayload::repeated(byte, length));
        }
    }
    out
}

/// Read a wordlist file and return one payload per non-empty line.
///
/// Each line (with `\r\n` / `\n` stripped) becomes a separate payload. Empty
/// lines and lines starting with `#` are skipped.
pub fn wordlist_payloads(path: &str) -> Result<Vec<OwnedFuzzPayload>> {
    let content = fs::read_to_string(path)?;
    let payloads = content
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| OwnedFuzzPayload {
            label: if line.len() > 40 {
                format!("{}...", &line[..40])
            } else {
                line.to_string()
            },
            data: line.as_bytes().to_vec(),
        })
        .collect();
    Ok(payloads)
}

/// Default payload set covering common vulnerability classes.
pub const PAYLOADS: &[FuzzPayload] = &[
    FuzzPayload { label: "null bytes",           data: &[0x00; 64] },
    FuzzPayload { label: "0xFF bytes",           data: &[0xFF; 64] },
    FuzzPayload { label: "long A string",        data: &[b'A'; 256] },
    FuzzPayload { label: "long newlines",        data: &[b'\n'; 64] },
    FuzzPayload { label: "format string",        data: b"%s%s%s%s%s%s%s%s%n%n%n%n" },
    FuzzPayload { label: "shell metacharacters", data: b";id;cat /etc/passwd;ls /\r\n" },
    FuzzPayload { label: "boundary bytes",       data: &[0x01, 0x7F, 0x80, 0xFE, 0xFF, 0x00] },
    FuzzPayload { label: "CRLF injection",       data: b"\r\n\r\n\r\n\r\n" },
    FuzzPayload { label: "AT commands",          data: b"AT+GMR\r\nAT+UART?\r\nAT&V\r\n" },
    FuzzPayload { label: "control characters",   data: &[0x01, 0x02, 0x03, 0x04, 0x1B, 0x7F] },
    FuzzPayload { label: "mixed binary",         data: b"AAA\x00BBB\xFF\xFECCC\r\n" },
];

/// Response substrings that suggest an anomalous or security-relevant outcome.
pub const INTERESTING_PATTERNS: &[&str] = &[
    // Crashes / faults
    "fault", "Fault", "panic", "exception", "Exception",
    "stack", "crash", "abort", "segfault", "overflow",
    // Errors
    "error", "Error", "ERROR", "syntax error", "invalid",
    // Shell / authentication exposure
    "root@", "# ", "$ ", "login:", "password:",
];
