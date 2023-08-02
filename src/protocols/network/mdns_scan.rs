use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use futures::{StreamExt, future, pin_mut};
use std::time::Duration;

/// mDNS service types to browse, with a human-readable label.
const SERVICE_TYPES: &[(&str, &str)] = &[
    ("_http._tcp.local", "HTTP"),
    ("_https._tcp.local", "HTTPS"),
    ("_ssh._tcp.local", "SSH"),
    ("_telnet._tcp.local", "Telnet"),
    ("_ftp._tcp.local", "FTP"),
    ("_mqtt._tcp.local", "MQTT"),
    ("_coap._udp.local", "CoAP"),
    ("_hap._tcp.local", "HomeKit (HAP)"),
    ("_matter._tcp.local", "Matter"),
    ("_googlecast._tcp.local", "Chromecast"),
];

/// Determine the severity level for a given mDNS service type.
fn severity_for_type(service_type: &str) -> Severity {
    if service_type.contains("telnet") {
        Severity::High
    } else if service_type.contains("_ftp.") {
        Severity::Medium
    } else if service_type.contains("_http._tcp.") {
        Severity::Low
    } else {
        Severity::Info
    }
}

/// Discover mDNS/DNS-SD services on the local network.
pub struct MdnsScanner {
    timeout_secs: u64,
}

/// Constructor and basic configuration for the MdnsScanner plugin.
impl MdnsScanner {
    pub fn new() -> Self {
        Self { timeout_secs: 10 }
    }
}

/// Default implementation for the MdnsScanner plugin.
impl Default for MdnsScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the MdnsScanner plugin.
impl Plugin for MdnsScanner {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Discover mDNS/DNS-SD services on the local network",
            description: "Browses mDNS for IoT-relevant service types (HTTP, MQTT, CoAP, \
                          HomeKit, Matter, Telnet, etc.) and reports resolved instances with \
                          hostname, address, port, and TXT records. Flags insecure protocols.",
            needs_root: false,
            args: &[
                CliArg { name: "timeout_secs", short: Some('t'), help: "How long to listen for responses (s)", value_name: "SECS", default: Some("5"), is_flag: false },
            ],
        )
    }

    /// Initialize the mDNS scanner plugin.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.timeout_secs = config.parse_or("timeout_secs", 5u64);
        Ok(())
    }

    /// Execute the mDNS scan and report discovered services.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);
        let timeout = Duration::from_secs(self.timeout_secs);

        // The Duration passed to discover::all is the query resend interval, not
        // a timeout. The stream never stops on its own. Each collection loop is wrapped
        // with async_std::future::timeout to enforce the deadline, then spawn all
        // service type queries in parallel on the thread pool.
        let all_responses: Vec<Vec<(String, String, mdns::Response)>> =
            async_std::task::block_on(async {
                let handles: Vec<_> = SERVICE_TYPES
                    .iter()
                    .map(|(stype, label)| {
                        let stype = stype.to_string();
                        let label = label.to_string();
                        async_std::task::spawn(async move {
                            let mut found: Vec<(String, String, mdns::Response)> = Vec::new();
                            // Send a query every second; the outer timeout stops collection.
                            let discovery =
                                match mdns::discover::all(&stype, Duration::from_secs(1)) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        tracing::warn!(stype, error = %e, "browse failed");
                                        return found;
                                    }
                                };
                            let _ = async_std::future::timeout(timeout, async {
                                let stream = discovery.listen();
                                pin_mut!(stream);
                                while let Some(Ok(response)) = stream.next().await {
                                    found.push((stype.clone(), label.clone(), response));
                                }
                            })
                            .await;
                            found
                        })
                    })
                    .collect();
                future::join_all(handles).await
            });

        let mut total = 0usize;
        for batch in all_responses {
            for (stype, label, response) in batch {
                let hostname = response.hostname().unwrap_or("-").to_string();
                let addr = response
                    .ip_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".into());
                let port = response
                    .port()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into());
                let txt: Vec<String> = response.txt_records().map(str::to_string).collect();

                let description = format!(
                    "Host: {hostname} | Address: {addr} | Port: {port}{}",
                    if txt.is_empty() {
                        String::new()
                    } else {
                        format!("\n  TXT: {}", txt.join(", "))
                    }
                );

                result.add(
                    PluginFinding::new(
                        severity_for_type(&stype),
                        format!("{label}: {hostname}"),
                        description,
                    )
                    .with_evidence(hostname),
                );
                total += 1;
            }
        }

        if total == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                "No mDNS services found",
                format!(
                    "No services responded within {}s. \
                     The network may have no mDNS-advertising devices, \
                     or a firewall is blocking multicast.",
                    self.timeout_secs
                ),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            result.finish(PluginStatus::Pass);
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(MdnsScanner::new()) as Box<dyn crate::Plugin>)
}
