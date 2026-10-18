use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use lapin::{Connection, ConnectionProperties};
use std::time::Duration;
use tokio::time::timeout;

const DEFAULT_PORT: u16 = 5672;
const DEFAULT_TIMEOUT_MS: u64 = 3000;

/// Default credentials to probe, ordered by likelihood.
const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("guest", "guest"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "rabbitmq"),
    ("rabbitmq", "rabbitmq"),
    ("user", "user"),
    ("root", "root"),
    ("admin", "guest"),
];

/// Construct an AMQP URI from the given components.
fn make_uri(host: &str, port: u16, user: &str, pass: &str, vhost: &str) -> String {
    // Percent-encode the vhost for the URI path segment.
    let encoded_vhost = vhost.replace('/', "%2F");
    format!("amqp://{user}:{pass}@{host}:{port}/{encoded_vhost}")
}

/// Result of an attempted AMQP connection.
#[derive(Debug)]
enum ConnResult {
    /// Credentials accepted - AMQP service confirmed running.
    Accepted,
    /// AMQP-level hard error (e.g., ACCESS_REFUSED) - service confirmed, creds wrong.
    Refused,
    /// IO error or timeout - service not reachable.
    Unreachable,
}

/// Attempt to connect to the AMQP broker using the provided URI and timeout.
async fn try_connect(uri: &str, timeout_ms: u64) -> ConnResult {
    let result = timeout(
        Duration::from_millis(timeout_ms),
        Connection::connect(uri, ConnectionProperties::default()),
    )
    .await;

    match result {
        Ok(Ok(conn)) => {
            conn.close(200, "".into()).await.ok();
            ConnResult::Accepted
        }
        Ok(Err(e)) if e.is_amqp_hard_error() || e.is_amqp_soft_error() => ConnResult::Refused,
        Ok(Err(_)) | Err(_) => ConnResult::Unreachable,
    }
}

/// Detect an AMQP broker and test for default credentials.
pub struct AmqpScanner {
    host: String,
    port: u16,
    vhost: String,
    timeout_ms: u64,
    try_creds: bool,
}

/// Implementation of the AmqpScanner struct.
impl AmqpScanner {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: DEFAULT_PORT,
            vhost: "/".to_string(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            try_creds: false,
        }
    }
}

/// Provide a default implementation for the AmqpScanner struct.
impl Default for AmqpScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Implement the Plugin trait for the AmqpScanner struct.
impl Plugin for AmqpScanner {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Detect an AMQP broker and test for default credentials",
            description: "Connects to the target AMQP port. \
                          Confirms whether an AMQP 0-9-1 broker is reachable and \
                          optionally probes a list of common default credentials \
                          using PLAIN authentication. Flags cleartext AMQP and \
                          accepted credentials as findings.",
            needs_root: false,
            args: &[
                CliArg { name: "host", short: Some('H'), help: "Target hostname or IP address", value_name: "HOST", default: None, is_flag: false },
                CliArg { name: "port", short: Some('p'), help: "AMQP port", value_name: "PORT", default: Some("5672"), is_flag: false },
                CliArg { name: "vhost", short: Some('V'), help: "Virtual host", value_name: "VHOST", default: Some("/"), is_flag: false },
                CliArg { name: "timeout_ms", short: Some('t'), help: "Connection timeout (ms)", value_name: "MS", default: Some("3000"), is_flag: false },
                CliArg { name: "try_creds", short: None, help: "Probe common default credentials", value_name: "", default: None, is_flag: true },
            ],
        )
    }

    /// Initialize the scanner with the provided plugin configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.get("host").unwrap_or_default().to_string();
        self.port = config.parse_or("port", DEFAULT_PORT);
        self.vhost = config.get_or("vhost", "/");
        self.timeout_ms = config.parse_or("timeout_ms", DEFAULT_TIMEOUT_MS);
        self.try_creds = config.get_or("try_creds", "false") == "true";
        Ok(())
    }

    /// Execute the scanning process.
    fn execute(&mut self) -> Result<PluginResult> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(self.scan_async())
    }
}

/// Implementation of the asynchronous scanning logic for the AmqpScanner struct.
impl AmqpScanner {
    async fn scan_async(&self) -> Result<PluginResult> {
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

        // Service detection
        // Use the first default credential pair to probe. If we get an AMQP
        // protocol error back we know the broker is running even without valid
        // credentials.
        let probe_uri = make_uri(&self.host, self.port, "guest", "guest", &self.vhost);
        let probe = try_connect(&probe_uri, self.timeout_ms).await;

        let service_confirmed = matches!(probe, ConnResult::Accepted | ConnResult::Refused);

        if !service_confirmed {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No AMQP service on {}:{}", self.host, self.port),
                "Connection timed out or was refused. The port may be closed.",
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!("AMQP broker on {}:{}", self.host, self.port),
            format!(
                "An AMQP 0-9-1 broker is listening on {}:{}.",
                self.host, self.port
            ),
        ));

        // Cleartext transport 
        if self.port == DEFAULT_PORT {
            result.add(PluginFinding::new(
                Severity::High,
                "Cleartext AMQP on port 5672",
                "AMQP 0-9-1 transmits credentials and all message payloads in \
                 plaintext. Use AMQPS (port 5671) with TLS.",
            ));
        }

        // Management UI hint
        result.add(PluginFinding::new(
            Severity::Info,
            "RabbitMQ management UI may be available on port 15672",
            "If the management plugin is enabled, the HTTP API and web UI are \
             accessible at http://<host>:15672 test with the http/banner plugin.",
        ));

        // Default credential check
        if self.try_creds {
            // guest/guest was already tried above. Record that result first.
            let mut accepted: Vec<(&str, &str)> = Vec::new();

            if matches!(probe, ConnResult::Accepted) {
                accepted.push(("guest", "guest"));
            }

            for &(user, pass) in DEFAULT_CREDS.iter().skip(1) {
                tracing::debug!(user, "trying credentials");
                let uri = make_uri(&self.host, self.port, user, pass, &self.vhost);
                match try_connect(&uri, self.timeout_ms).await {
                    ConnResult::Accepted => {
                        tracing::info!(user, "credentials accepted");
                        accepted.push((user, pass));
                    }
                    ConnResult::Refused => {}
                    ConnResult::Unreachable => {
                        tracing::debug!(user, "connection error during credential test");
                    }
                }
            }

            if accepted.is_empty() {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "No default credentials accepted",
                    format!(
                        "Tested {} credential pair(s); all were rejected.",
                        DEFAULT_CREDS.len()
                    ),
                ));
            } else {
                for (user, pass) in &accepted {
                    result.add(
                        PluginFinding::new(
                            Severity::Critical,
                            format!("Default credentials accepted: {user}/{pass}"),
                            format!(
                                "The broker on {}:{} accepted {user}/{pass} for vhost '{}'. \
                                 Change this password immediately.",
                                self.host, self.port, self.vhost
                            ),
                        )
                        .with_evidence(format!("{user}:{pass}")),
                    );
                }
            }
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(AmqpScanner::new()) as Box<dyn crate::Plugin>)
}
