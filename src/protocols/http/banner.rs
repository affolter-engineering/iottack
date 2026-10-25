use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// A parsed HTTP response: status line + headers + optional truncated body.
struct HttpResponse {
    status: u16,
    reason: String,
    headers: HashMap<String, String>,
    body_preview: String,
}

/// Send a minimal HTTP/1.1 GET request and parse the response.
fn http_get(host: &str, port: u16, path: &str, timeout: Duration) -> Result<HttpResponse> {
    let addr_str = format!("{host}:{port}");
    let addr: SocketAddr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {addr_str}"))?;

    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: iottack\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );

    let mut stream = stream;
    stream.write_all(request.as_bytes())?;

    let mut reader = BufReader::new(&mut stream);

    // Status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status_line = status_line.trim_end();
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().unwrap_or("");
    let status: u16 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let reason = parts.next().unwrap_or("").to_string();

    // Headers
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    // Read up to 2 KiB of body for default-page detection.
    let mut body_bytes = vec![0u8; 2048];
    let n = std::io::Read::read(&mut reader, &mut body_bytes).unwrap_or(0);
    let body_preview = String::from_utf8_lossy(&body_bytes[..n]).to_string();

    Ok(HttpResponse {
        status,
        reason,
        headers,
        body_preview,
    })
}

/// Returns true if the Server header value looks like it discloses a version number.
fn has_version(value: &str) -> bool {
    value.contains('/') && value.chars().any(|c| c.is_ascii_digit())
}

/// Detect common default/test pages by body content.
fn detect_default_page(body: &str) -> Option<&'static str> {
    let body_lc = body.to_lowercase();
    if body_lc.contains("apache2 default page") || body_lc.contains("apache2 ubuntu default") {
        Some("Apache2 default page")
    } else if body_lc.contains("welcome to nginx") {
        Some("nginx default page")
    } else if body_lc.contains("iis windows server")
        || body_lc.contains("internet information services")
    {
        Some("IIS default page")
    } else if body_lc.contains("lighttpd - it works") {
        Some("lighttpd default page")
    } else if body_lc.contains("test page for the apache") {
        Some("Apache test page")
    } else {
        None
    }
}

/// Grab HTTP banners and check response headers from a web server.
pub struct BannerPlugin {
    host: String,
    port: u16,
    path: String,
    timeout_ms: u64,
}

/// Plugin for grabbing HTTP banners and checking response headers from a web server.
impl BannerPlugin {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: 80,
            path: "/".to_string(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

/// Default implementation for the BannerPlugin.
impl Default for BannerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the Plugin trait for the BannerPlugin.
impl Plugin for BannerPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Grab the HTTP banner and check response headers from a web server",
            description: "Sends a GET request and inspects the response: \
                          server and technology headers, HTTP status, \
                          version disclosure, missing security headers \
                          (HSTS, X-Frame-Options, X-Content-Type-Options, CSP), \
                          and default/test pages. Flags cleartext HTTP and \
                          information disclosure findings.",
            needs_root: false,
            args: &[
                CliArg { name: "host", short: Some('H'), help: "Target hostname or IP address", value_name: "HOST", default: None, is_flag: false },
                CliArg { name: "port", short: Some('p'), help: "TCP port", value_name: "PORT", default: Some("80"), is_flag: false },
                CliArg { name: "path", short: Some('u'), help: "Request path", value_name: "PATH", default: Some("/"), is_flag: false },
                CliArg { name: "timeout_ms", short: Some('t'), help: "Connect and read timeout (ms)", value_name: "MS", default: Some("5000"), is_flag: false },
            ],
        )
    }

    /// Initialize the BannerPlugin with the provided configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.get("host").unwrap_or_default().to_string();
        self.port = config.parse_or("port", 80u16);
        self.path = config.get_or("path", "/");
        self.timeout_ms = config.parse_or("timeout_ms", DEFAULT_TIMEOUT_MS);
        Ok(())
    }

    /// Execute the BannerPlugin and return the results.
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

        let timeout = Duration::from_millis(self.timeout_ms);
        let resp = match http_get(&self.host, self.port, &self.path, timeout) {
            Ok(r) => r,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Connection failed: {}:{}", self.host, self.port),
                    e.to_string(),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        let h = &resp.headers;
        let target = format!("{}:{}{}", self.host, self.port, self.path);

        // Status
        result.add(PluginFinding::new(
            Severity::Info,
            format!("HTTP {} {}", resp.status, resp.reason),
            format!("Target: {target}"),
        ));

        // Server/technology headers
        if let Some(server) = h.get("server") {
            let version_disclosure = has_version(server);
            let sev = if version_disclosure {
                Severity::Medium
            } else {
                Severity::Info
            };
            let desc = if version_disclosure {
                "Server header discloses software version. Consider suppressing or \
                 generalizing this header."
                    .to_string()
            } else {
                "Server header identifies the software without a version number.".to_string()
            };
            result.add(
                PluginFinding::new(sev, format!("Server header: {server}"), desc)
                    .with_evidence(server.clone()),
            );
        } else {
            result.add(PluginFinding::new(
                Severity::Info,
                "No Server header",
                "The server does not send a Server header.",
            ));
        }

        if let Some(powered) = h.get("x-powered-by") {
            result.add(
                PluginFinding::new(
                    Severity::Medium,
                    format!("X-Powered-By header: {powered}"),
                    "X-Powered-By discloses the application framework or runtime. \
                     Consider removing this header.",
                )
                .with_evidence(powered.clone()),
            );
        }

        if let Some(via) = h.get("via") {
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    format!("Via header: {via}"),
                    "Via header indicates the presence of a proxy or load balancer.",
                )
                .with_evidence(via.clone()),
            );
        }

        // Cleartext HTTP
        if self.port == 80 {
            let redirects_to_https = h
                .get("location")
                .map(|l| l.starts_with("https://"))
                .unwrap_or(false)
                && (resp.status == 301
                    || resp.status == 302
                    || resp.status == 307
                    || resp.status == 308);

            if redirects_to_https {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "HTTP redirects to HTTPS",
                    format!(
                        "Port 80 redirects to: {}",
                        h.get("location").map(String::as_str).unwrap_or("-")
                    ),
                ));
            } else {
                result.add(PluginFinding::new(
                    Severity::High,
                    "Cleartext HTTP on port 80",
                    "Service responds to plain HTTP without redirecting to HTTPS. \
                     Credentials and session data are transmitted unencrypted.",
                ));
            }
        }

        // Security headers
        if !h.contains_key("strict-transport-security") && self.port == 443 {
            result.add(PluginFinding::new(
                Severity::Medium,
                "Missing Strict-Transport-Security (HSTS)",
                "HSTS is absent. Browsers are not instructed to enforce HTTPS, \
                 leaving users vulnerable to protocol downgrade attacks.",
            ));
        }

        if !h.contains_key("x-frame-options") && !h.contains_key("content-security-policy") {
            result.add(PluginFinding::new(
                Severity::Low,
                "Missing X-Frame-Options / CSP frame-ancestors",
                "No clickjacking protection header found.",
            ));
        }

        if !h.contains_key("x-content-type-options") {
            result.add(PluginFinding::new(
                Severity::Low,
                "Missing X-Content-Type-Options",
                "The server does not send X-Content-Type-Options: nosniff. \
                 Browsers may MIME-sniff responses away from the declared content type.",
            ));
        }

        if !h.contains_key("content-security-policy") {
            result.add(PluginFinding::new(
                Severity::Low,
                "Missing Content-Security-Policy",
                "No CSP header found. XSS and data-injection risks are not mitigated \
                 at the transport layer.",
            ));
        }

        // Authentication
        if resp.status == 401 {
            let auth_scheme = h
                .get("www-authenticate")
                .map(|v| {
                    let scheme = v.split_whitespace().next().unwrap_or(v.as_str());
                    scheme.to_string()
                })
                .unwrap_or_else(|| "unknown".to_string());

            let basic_auth = auth_scheme.to_lowercase() == "basic";
            let sev = if basic_auth {
                Severity::High
            } else {
                Severity::Info
            };
            let desc = if basic_auth {
                "HTTP Basic authentication transmits credentials in Base64 over cleartext \
                 HTTP. Use Digest or move to HTTPS."
                    .to_string()
            } else {
                format!("WWW-Authenticate scheme: {auth_scheme}")
            };
            result.add(
                PluginFinding::new(
                    sev,
                    format!("HTTP authentication required ({auth_scheme})"),
                    desc,
                )
                .with_evidence(h.get("www-authenticate").cloned().unwrap_or_default()),
            );
        }

        // Default pages
        if let Some(page_name) = detect_default_page(&resp.body_preview) {
            result.add(PluginFinding::new(
                Severity::Medium,
                format!("{page_name} detected"),
                "The server is serving its default installation page. \
                 This confirms the software identity and suggests the server has not \
                 been customized after installation.",
            ));
        }

        // Cookie flags
        for (key, value) in h {
            if key == "set-cookie" {
                let lc = value.to_lowercase();
                let missing_secure = !lc.contains("secure");
                let missing_httponly = !lc.contains("httponly");
                if missing_secure || missing_httponly {
                    let mut issues = Vec::new();
                    if missing_secure {
                        issues.push("Secure");
                    }
                    if missing_httponly {
                        issues.push("HttpOnly");
                    }
                    result.add(
                        PluginFinding::new(
                            Severity::Medium,
                            format!("Cookie missing flag(s): {}", issues.join(", ")),
                            format!("Set-Cookie: {value}"),
                        )
                        .with_evidence(value.clone()),
                    );
                }
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(BannerPlugin::new()) as Box<dyn crate::Plugin>)
}
