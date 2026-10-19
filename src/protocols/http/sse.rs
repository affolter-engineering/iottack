use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_MS: u64 = 5000;
const DEFAULT_DURATION_S: u64 = 10;
const DEFAULT_MAX_EVENTS: usize = 100;

/// Sensitive keyword list checked against event data payloads.
const SENSITIVE_KEYWORDS: &[&str] =
    &["password", "token", "secret", "key", "auth", "credential", "private", "username", "serial"];

/// Representation of a single SSE event.
struct SseEvent {
    event_type: String,
    data: String,
}

/// Consume Server-Sent Events from a device HTTP endpoint.
pub struct SsePlugin {
    host: String,
    port: u16,
    path: String,
    timeout_ms: u64,
    duration_s: u64,
    max_events: usize,
}

/// Implementation of the SSE plugin.
impl SsePlugin {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 80,
            path: String::from("/events"),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            duration_s: DEFAULT_DURATION_S,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

/// Default implementation for the SSE plugin.
impl Default for SsePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implement the Plugin trait for the SSE plugin.
impl Plugin for SsePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Consume Server-Sent Events (SSE/EventSource) from a device endpoint",
            description: "Connects to an HTTP EventSource endpoint and collects \
                          Server-Sent Events for a configurable duration. Analyses \
                          the stream for open access, cleartext transmission, CORS \
                          policy, event rate, event types and potentially sensitive \
                          data disclosed in event payloads.",
            needs_root: false,
            args: &[
                CliArg { name: "host", short: Some('H'), help: "Target hostname or IP address", value_name: "HOST", default: None, is_flag: false },
                CliArg { name: "port", short: Some('p'), help: "TCP port", value_name: "PORT", default: Some("80"), is_flag: false },
                CliArg { name: "path", short: Some('u'), help: "EventSource endpoint path", value_name: "PATH",  default: Some("/events"), is_flag: false },
                CliArg { name: "timeout_ms", short: Some('t'), help: "Connection timeout (ms)", value_name: "MS", default: Some("5000"), is_flag: false },
                CliArg { name: "duration_s", short: Some('d'), help: "How long to collect events (seconds)", value_name: "SECS", default: Some("10"), is_flag: false },
                CliArg { name: "max_events", short: Some('n'), help: "Maximum number of events to collect", value_name: "COUNT", default: Some("100"), is_flag: false },
            ],
        )
    }

    /// Initialize the SSE plugin with the provided configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.get("host").unwrap_or_default().to_string();
        self.port = config.parse_or("port", 80u16);
        self.path = config.get_or("path", "/events");
        self.timeout_ms = config.parse_or("timeout_ms", DEFAULT_TIMEOUT_MS);
        self.duration_s = config.parse_or("duration_s", DEFAULT_DURATION_S);
        self.max_events = config.parse_or("max_events", DEFAULT_MAX_EVENTS);
        Ok(())
    }

    /// Execute the SSE plugin, connecting to the target and collecting events.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        if self.host.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No host specified",
                "Use --host to provide a target address.",
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        let connect_timeout = Duration::from_millis(self.timeout_ms);
        let addr_str = format!("{}:{}", self.host, self.port);
        let addr: SocketAddr = match addr_str.to_socket_addrs()?.next() {
            Some(a) => a,
            None => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Could not resolve {addr_str}"),
                    "DNS resolution failed.",
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        let stream = match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(s) => s,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Connection failed: {addr_str}"),
                    e.to_string(),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        // Short per-read timeout; the outer loop enforces the overall duration.
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.set_write_timeout(Some(connect_timeout))?;

        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: iottack\r\n\
             Accept: text/event-stream\r\n\
             Cache-Control: no-cache\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = self.path,
            host = self.host,
        );

        let mut stream = stream;
        stream.write_all(request.as_bytes())?;

        let mut reader = BufReader::new(&mut stream);

        // Parse status line
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;
        let status_line = status_line.trim_end().to_string();
        let mut parts = status_line.splitn(3, ' ');
        let _http_version = parts.next().unwrap_or("");
        let status: u16 = parts.next().unwrap_or("0").parse().unwrap_or(0);
        let reason = parts.next().unwrap_or("").to_string();

        // Parse response headers
        let mut headers: HashMap<String, String> = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim_end().to_string();
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!("HTTP {status} {reason}"),
            format!("Target: {}:{}{}", self.host, self.port, self.path),
        ));

        // Authentication / access control
        if status == 401 || status == 403 {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("Access denied (HTTP {status})"),
                "The EventSource endpoint requires authentication or is forbidden.",
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        if status != 200 {
            result.add(PluginFinding::new(
                Severity::Medium,
                format!("Unexpected HTTP status {status}"),
                "The server did not return 200 OK for the EventSource request.",
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        // Content-Type validation
        let content_type = headers.get("content-type").cloned().unwrap_or_default();
        if content_type.contains("text/event-stream") {
            result.add(PluginFinding::new(
                Severity::Info,
                "Valid EventSource endpoint",
                "Server responds with Content-Type: text/event-stream.",
            ));
        } else {
            result.add(
                PluginFinding::new(
                    Severity::Medium,
                    format!("Unexpected Content-Type: {content_type}"),
                    "The server did not respond with 'text/event-stream'. \
                     Ensure the correct endpoint path is used.",
                )
                .with_evidence(format!("Content-Type: {content_type}")),
            );
        }

        // Cleartext transmission
        if self.port == 80 {
            result.add(PluginFinding::new(
                Severity::High,
                "SSE stream delivered over cleartext HTTP",
                "Server-Sent Events are served on port 80 without TLS. All event \
                 data (sensor readings, device state, tokens) is visible to passive \
                 observers on the network path.",
            ));
        }

        // Open access
        result.add(PluginFinding::new(
            Severity::Medium,
            "SSE endpoint accessible without authentication",
            "The EventSource endpoint returned a stream without requiring any \
             credentials. Restrict access if the stream carries sensitive device state.",
        ));

        // CORS policy
        match headers.get("access-control-allow-origin").map(String::as_str) {
            Some("*") => {
                result.add(
                    PluginFinding::new(
                        Severity::Medium,
                        "Wildcard CORS policy on SSE endpoint",
                        "Access-Control-Allow-Origin: * allows any web origin to read \
                         the event stream from a browser. Restrict to specific trusted \
                         origins if the stream carries sensitive data.",
                    )
                    .with_evidence("Access-Control-Allow-Origin: *"),
                );
            }
            Some(origin) => {
                result.add(
                    PluginFinding::new(
                        Severity::Info,
                        format!("CORS origin restricted to: {origin}"),
                        "Cross-origin access is limited to a specific origin.",
                    )
                    .with_evidence(format!("Access-Control-Allow-Origin: {origin}")),
                );
            }
            None => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "No CORS header on SSE endpoint",
                    "The server does not send Access-Control-Allow-Origin.",
                ));
            }
        }

        // Collect SSE events
        let deadline = Instant::now() + Duration::from_secs(self.duration_s);
        let mut events: Vec<SseEvent> = Vec::new();
        let mut event_type_buf = String::from("message");
        let mut data_buf: Vec<String> = Vec::new();
        let mut event_counts: HashMap<String, usize> = HashMap::new();

        'stream: loop {
            if Instant::now() >= deadline || events.len() >= self.max_events {
                break;
            }

            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if Instant::now() >= deadline {
                        break 'stream;
                    }
                    continue;
                }
                Err(_) => break,
            }

            let line = line.trim_end_matches(['\r', '\n']).to_string();

            if line.is_empty() {
                // Blank line dispatches the buffered event.
                if !data_buf.is_empty() {
                    *event_counts.entry(event_type_buf.clone()).or_insert(0) += 1;
                    events.push(SseEvent {
                        event_type: event_type_buf.clone(),
                        data: data_buf.join("\n"),
                    });
                }
                event_type_buf = String::from("message");
                data_buf.clear();
            } else if let Some(val) = line.strip_prefix("event:") {
                event_type_buf = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("data:") {
                data_buf.push(val.trim().to_string());
            }
            // id:, retry:, and comment lines (":") are intentionally ignored.
        }

        // Report event statistics
        let total = events.len();
        if total == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No events received in {} s", self.duration_s),
                "The connection was established but the server delivered no events \
                 during the collection window.",
            ));
        } else {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("Received {total} event(s) in {} s", self.duration_s),
                format!(
                    "Average rate: {:.2} events/s",
                    total as f64 / self.duration_s as f64
                ),
            ));

            let type_summary: Vec<String> =
                event_counts.iter().map(|(t, c)| format!("{c}x {t}")).collect();
            result.add(PluginFinding::new(
                Severity::Info,
                format!("Event types observed: {}", type_summary.join(", ")),
                "Unique event type names seen in the stream.",
            ));

            // Sensitive data scan
            let mut hits: Vec<String> = Vec::new();
            for ev in &events {
                let lowercase = ev.data.to_lowercase();
                for keyword in SENSITIVE_KEYWORDS {
                    if lowercase.contains(keyword) {
                        hits.push(format!("'{}' in '{}' event", keyword, ev.event_type));
                        break;
                    }
                }
            }
            if !hits.is_empty() {
                result.add(PluginFinding::new(
                    Severity::High,
                    "Potentially sensitive data in event stream",
                    format!(
                        "Event payloads contain keywords suggesting sensitive \
                         information: {}",
                        hits.join("; ")
                    ),
                ));
            }

            // First event sample
            if let Some(first) = events.first() {
                let preview: String = first.data.chars().take(256).collect();
                result.add(
                    PluginFinding::new(
                        Severity::Info,
                        format!("First event sample (type: {})", first.event_type),
                        format!("data: {preview}"),
                    )
                    .with_evidence(preview),
                );
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(SsePlugin::new()) as Box<dyn crate::Plugin>)
}
