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

/// Generate every combination of `charset` bytes up to `max_length` characters.
///
/// Uses a Cartesian-product approach: for each length L from 1 to `max_length`
/// every possible string of exactly L bytes drawn from `charset` is emitted.
/// For charset `"ab"` and max_length `2` this yields:
/// `a`, `b`, `aa`, `ab`, `ba`, `bb`.
///
/// Total payloads = |charset|^1 + |charset|^2 + … + |charset|^max_length.
/// Keep `max_length` small for large charsets to avoid generating millions of payloads.
pub fn charset_payloads(charset: &str, max_length: usize) -> Vec<OwnedFuzzPayload> {
    let bytes: Vec<u8> = charset.bytes().collect();
    if bytes.is_empty() || max_length == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    // `current` holds all strings of the current length being generated.
    let mut current: Vec<Vec<u8>> = bytes.iter().map(|&b| vec![b]).collect();

    for _ in 0..max_length {
        for combo in &current {
            let label: String = combo
                .iter()
                .flat_map(|b| b.escape_ascii())
                .map(char::from)
                .collect();
            out.push(OwnedFuzzPayload { label, data: combo.clone() });
        }
        // Extend every current string with every byte to build the next length.
        current = current
            .iter()
            .flat_map(|combo| {
                bytes.iter().map(move |&b| {
                    let mut next = combo.clone();
                    next.push(b);
                    next
                })
            })
            .collect();
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
