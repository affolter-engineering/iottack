use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::{bail, Result};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

const DEFAULT_TIMEOUT_MS: u64 = 3000;
const BANNER_BUF_SIZE: usize = 4096;

struct ServiceHint {
    name: &'static str,
    /// Probe bytes sent after connect to elicit a response. `None` = passive read.
    probe: Option<&'static [u8]>,
    /// ASCII text substrings matched against the banner string.
    keywords: &'static [&'static str],
    /// Raw byte sequences matched against the banner bytes (for binary protocols).
    byte_keywords: &'static [&'static [u8]],
    severity: Severity,
}

static HINTS: &[ServiceHint] = &[
    ServiceHint {
        name: "SSH",
        probe: None,
        keywords: &["SSH-"],
        byte_keywords: &[],
        severity: Severity::Info,
    },
    ServiceHint {
        name: "FTP",
        probe: None,
        keywords: &["220 ", "vsftpd", "ProFTPD", "FileZilla"],
        byte_keywords: &[],
        severity: Severity::High,
    },
    ServiceHint {
        name: "Telnet",
        probe: None,
        keywords: &[],
        // IAC DO/IAC WILL option negotiation bytes
        byte_keywords: &[&[0xff, 0xfd], &[0xff, 0xfb]],
        severity: Severity::High,
    },
    ServiceHint {
        name: "SMTP",
        probe: None,
        keywords: &["220 ", "ESMTP", "Postfix", "Sendmail"],
        byte_keywords: &[],
        severity: Severity::Medium,
    },
    ServiceHint {
        name: "POP3",
        probe: None,
        keywords: &["+OK "],
        byte_keywords: &[],
        severity: Severity::Medium,
    },
    ServiceHint {
        name: "IMAP",
        probe: None,
        keywords: &["* OK ", "IMAP"],
        byte_keywords: &[],
        severity: Severity::Medium,
    },
    ServiceHint {
        name: "VNC",
        probe: None,
        keywords: &["RFB 0"],
        byte_keywords: &[],
        severity: Severity::High,
    },
    ServiceHint {
        name: "HTTP",
        probe: Some(b"GET / HTTP/1.0\r\n\r\n"),
        keywords: &["HTTP/1.", "HTTP/2", "Server:", "Content-Type:"],
        byte_keywords: &[],
        severity: Severity::Low,
    },
    ServiceHint {
        name: "Redis",
        probe: Some(b"PING\r\n"),
        keywords: &["+PONG", "-ERR"],
        byte_keywords: &[],
        severity: Severity::High,
    },
    ServiceHint {
        name: "MQTT",
        // CONNECT packet: MQTT 3.1.1, clean session, client-id "test"
        probe: Some(b"\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test"),
        keywords: &[],
        // CONNACK: packet type 0x20, remaining length 0x02
        byte_keywords: &[&[0x20, 0x02]],
        severity: Severity::High,
    },
    ServiceHint {
        name: "Modbus/TCP",
        // Read Holding Registers: unit 1, addr 0, count 1
        probe: Some(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"),
        keywords: &[],
        // Response echoes transaction ID 0x00 0x01 and protocol ID 0x00 0x00
        byte_keywords: &[&[0x00, 0x01, 0x00, 0x00]],
        severity: Severity::High,
    },
];

fn banner_matches(hint: &ServiceHint, banner: &str, banner_bytes: &[u8]) -> bool {
    hint.keywords.iter().any(|kw| banner.contains(kw))
        || hint
            .byte_keywords
            .iter()
            .any(|pat| banner_bytes.windows(pat.len()).any(|w| w == *pat))
}

fn classify(banner: &str, banner_bytes: &[u8]) -> Option<(&'static str, Severity)> {
    HINTS
        .iter()
        .find(|h| banner_matches(h, banner, banner_bytes))
        .map(|h| (h.name, h.severity.clone()))
}

fn severity_for_banner(banner: &str) -> Severity {
    let version_patterns = ["version", "/1.", "/2.", "OpenSSH", "Apache", "nginx"];
    if version_patterns
        .iter()
        .any(|p| banner.to_lowercase().contains(p))
    {
        Severity::Medium
    } else {
        Severity::Info
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() && c != '\n' { '.' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Parse a port specification into a sorted, deduplicated list of port numbers.
///
/// Accepts:
/// - Single ports: `80`
/// - Comma-separated lists: `80,443,8080`
/// - Ranges (inclusive): `8080-8090`, `8080...8090` or `8080..8090`
/// - Combinations: `22,80,443,8080-8090`
fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Try range separators in order of specificity.
        let range = part
            .split_once("...")
            .or_else(|| part.split_once(".."))
            .or_else(|| part.split_once('-'));

        if let Some((start_str, end_str)) = range {
            let start: u16 = start_str.trim().parse().map_err(|_| {
                anyhow::anyhow!("invalid port number '{}' in '{}'", start_str.trim(), part)
            })?;
            let end: u16 = end_str.trim().parse().map_err(|_| {
                anyhow::anyhow!("invalid port number '{}' in '{}'", end_str.trim(), part)
            })?;
            if start > end {
                bail!("port range start ({start}) must be ≤ end ({end})");
            }
            ports.extend(start..=end);
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port number '{part}'"))?;
            ports.push(p);
        }
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Parse "a.b.c.d/prefix" into host addresses for the subnet.
/// /32 -> single address, /31 -> both addresses. Others -> skip network and broadcast.
fn parse_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>> {
    let (address_part, prefix_part) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid CIDR '{cidr}': expected a.b.c.d/prefix"))?;

    let base: Ipv4Addr = address_part
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IPv4 address '{address_part}'"))?;

    let prefix_len: u8 = prefix_part
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid prefix length '{prefix_part}'"))?;

    if prefix_len > 32 {
        bail!("prefix length must be 0-32, got {prefix_len}");
    }

    let mask: u32 = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    let network = u32::from(base) & mask;
    let broadcast = network | !mask;

    let address = if prefix_len == 32 {
        vec![Ipv4Addr::from(network)]
    } else if prefix_len == 31 {
        vec![Ipv4Addr::from(network), Ipv4Addr::from(broadcast)]
    } else {
        (network + 1..broadcast).map(Ipv4Addr::from).collect()
    };

    Ok(address)
}

/// Grab the banner from a single host:port. Returns zero or one finding.
///
/// `active_probes`: when false, skips hints that require sending a probe (used
/// during subnet/port sweeps to reduce noise and latency).
fn grab_banner(
    host: &str,
    port: u16,
    timeout: Duration,
    probe: &str,
    active_probes: bool,
) -> Option<PluginFinding> {
    let address: SocketAddr = format!("{host}:{port}").parse().ok()?;

    let stream = TcpStream::connect_timeout(&address, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let mut stream = stream;

    if !probe.is_empty() {
        let _ = stream.write_all(probe.as_bytes());
    }

    let mut buf = vec![0u8; BANNER_BUF_SIZE];
    let n = stream.read(&mut buf).unwrap_or(0);

    if n == 0 {
        if !active_probes {
            return Some(PluginFinding::new(
                Severity::Info,
                format!("Open port {host}:{port}"),
                "TCP connection accepted but no banner received.",
            ));
        }
        return try_active_probes(host, port, timeout);
    }

    let banner_bytes = &buf[..n];
    let banner = String::from_utf8_lossy(banner_bytes).to_string();
    let display = sanitize(&banner);

    let (title, sev) = if let Some((svc_name, sev)) = classify(&banner, banner_bytes) {
        (format!("{svc_name} on {host}:{port}"), sev)
    } else {
        (
            format!("Unknown service on {host}:{port}"),
            severity_for_banner(&banner),
        )
    };

    Some(PluginFinding::new(sev, title, format!("Banner: {display}")).with_evidence(banner))
}

fn try_active_probes(host: &str, port: u16, timeout: Duration) -> Option<PluginFinding> {
    let address: SocketAddr = format!("{host}:{port}").parse().ok()?;

    for hint in HINTS {
        if let Some(probe) = hint.probe {
            let Ok(stream) = TcpStream::connect_timeout(&address, timeout) else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let mut stream = stream;
            if stream.write_all(probe).is_err() {
                continue;
            }
            let mut buf = vec![0u8; BANNER_BUF_SIZE];
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                continue;
            }
            let banner_bytes = &buf[..n];
            let banner = String::from_utf8_lossy(banner_bytes).to_string();
            if banner_matches(hint, &banner, banner_bytes) {
                return Some(
                    PluginFinding::new(
                        hint.severity.clone(),
                        format!("{} on {host}:{port}", hint.name),
                        format!("Banner: {}", sanitize(&banner)),
                    )
                    .with_evidence(banner),
                );
            }
        }
    }
    None
}

/// Connect to a TCP service (or sweep a subnet / port range) and capture initial banners.
pub struct TcpBannerGrabber {
    host: String,
    net: String,
    port: u16,
    ports: Vec<u16>,
    all_ports: bool,
    timeout_ms: u64,
    probe: String,
}

/// Create a new TcpBannerGrabber instance.
impl TcpBannerGrabber {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            net: String::new(),
            port: 80,
            ports: Vec::new(),
            all_ports: false,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            probe: String::new(),
        }
    }

    /// Return the effective port list, respecting precedence:
    /// --all-ports > --ports > --port
    fn resolved_ports(&self) -> Vec<u16> {
        if self.all_ports {
            (1u16..=65535).collect()
        } else if !self.ports.is_empty() {
            self.ports.clone()
        } else {
            vec![self.port]
        }
    }
}

/// Default implementation for TcpBannerGrabber.
impl Default for TcpBannerGrabber {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin implementation for TcpBannerGrabber.
impl Plugin for TcpBannerGrabber {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Connect to a TCP service and capture the initial banner",
            description: "Opens a TCP connection and reads the service banner. \
                          Supports single hosts (--host), subnet sweeps (--net CIDR), \
                          single ports (--port), port lists/ranges (--ports) and \
                          full port sweeps (--all-ports). \
                          Identifies SSH, FTP, Telnet, HTTP, SMTP, POP3, IMAP, MQTT, \
                          Modbus/TCP, Redis and VNC. \
                          Flags cleartext and unauthenticated services.",
            needs_root: false,
            args: &[
                CliArg { name: "host", short: Some('H'), help: "Target hostname or IP address", value_name: "HOST", default: None, is_flag: false },
                CliArg { name: "net", short: Some('n'), help: "IPv4 CIDR subnet to sweep, e.g., 192.168.1.0/24 (overrides --host)", value_name: "CIDR", default: None, is_flag: false },
                CliArg { name: "port", short: Some('p'), help: "Single TCP port (default when --ports/--all-ports are absent)", value_name: "PORT", default: Some("80"), is_flag: false },
                CliArg { name: "ports", short: Some('P'), help: "Port list or ranges, e.g., 22,80,443, 8080-8090 or 22,8000...9000", value_name: "PORTS", default: None, is_flag: false },
                CliArg { name: "all_ports", short: Some('A'), help: "Sweep all TCP ports 1-65535 (overrides --port and --ports)", value_name: "", default: None, is_flag: true },
                CliArg { name: "timeout_ms", short: Some('t'), help: "Connect and read timeout (ms). Use 200-500 for sweeps", value_name: "MS", default: Some("3000"), is_flag: false },
                CliArg { name: "probe", short: None,  help: "Data to send after connecting (empty = passive read)", value_name: "PROBE", default: Some(""), is_flag: false },
            ],
        )
    }

    /// Initializes the plugin with the given configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.get("host").unwrap_or_default().to_string();
        self.net = config.get("net").unwrap_or_default().to_string();
        self.port = config.parse_or("port", 80u16);
        self.all_ports = config.get_or("all_ports", "false") == "true";
        self.timeout_ms = config.parse_or("timeout_ms", DEFAULT_TIMEOUT_MS);
        self.probe = config.get("probe").unwrap_or_default().to_string();

        if let Some(spec) = config.get("ports") {
            if !spec.is_empty() {
                self.ports = parse_ports(spec)?;
            }
        }

        Ok(())
    }

    /// Executes the plugin's main logic.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        if !self.net.is_empty() {
            return self.execute_sweep(&mut result);
        }

        if self.host.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No target specified",
                "Use --host <HOST> for a single target or --net <CIDR> for a subnet sweep.",
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        let timeout = Duration::from_millis(self.timeout_ms);
        let ports = self.resolved_ports();
        let multi = ports.len() > 1;
        let mut found = 0usize;

        for port in &ports {
            match grab_banner(&self.host, *port, timeout, &self.probe, !multi) {
                Some(finding) => {
                    result.add(finding);
                    found += 1;
                }
                None => {
                    if multi {
                        tracing::debug!(host = %self.host, port, "no response");
                    }
                }
            }
        }

        if found == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No open ports found on {}", self.host),
                format!(
                    "Checked {} port(s). Host did not respond or connections were refused.",
                    ports.len()
                ),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            result.finish(PluginStatus::Pass);
        }

        Ok(result)
    }
}

/// Executes a subnet sweep for the plugin.
impl TcpBannerGrabber {
    fn execute_sweep(&self, result: &mut PluginResult) -> Result<PluginResult> {
        let hosts = parse_cidr(&self.net)?;
        let ports = self.resolved_ports();
        let timeout = Duration::from_millis(self.timeout_ms);
        let probe = &self.probe;

        tracing::info!(
            net = %self.net,
            ports = ports.len(),
            hosts = hosts.len(),
            timeout_ms = self.timeout_ms,
            "starting subnet sweep"
        );

        let mut found = 0usize;
        for addr in &hosts {
            let host = addr.to_string();
            for port in &ports {
                if let Some(finding) = grab_banner(&host, *port, timeout, probe, false) {
                    tracing::debug!(host, port, "open");
                    result.add(finding);
                    found += 1;
                }
            }
        }

        if found == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No open hosts found in {} on {} port(s)", self.net, ports.len()),
                format!(
                    "Scanned {} address(es) x {} port(s). \
                     Try lowering --timeout-ms or verify the subnet.",
                    hosts.len(),
                    ports.len()
                ),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            result.finish(PluginStatus::Pass);
        }

        Ok(result.clone())
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(TcpBannerGrabber::new()) as Box<dyn crate::Plugin>)
}
