use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use bacnet_rs::client::{BacnetClient, BacnetTarget};
use bacnet_rs::object::ObjectIdentifier;
use bacnet_rs::object::object_type::ObjectType;
use bacnet_rs::object::property_identifier::PropertyIdentifier;
use std::net::SocketAddr;
use std::time::Duration;

use super::BACNET_DEFAULT_PORT;

/// Discover BACnet/IP devices via Who-Is/I-Am and read Device-object properties.
pub struct BacnetScanner {
    host: Option<String>,
    port: u16,
    timeout_ms: u64,
    device_id: Option<u32>,
}

/// BacnetScanner implementation
impl BacnetScanner {
    pub fn new() -> Self {
        Self { host: None, port: BACNET_DEFAULT_PORT, timeout_ms: 3_000, device_id: None }
    }
}

/// Default implementation for BacnetScanner
impl Default for BacnetScanner {
    fn default() -> Self { Self::new() }
}

/// Plugin implementation for BacnetScanner
impl Plugin for BacnetScanner {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Discover BACnet/IP devices and read device properties unauthenticated",
            description: "Sends a BACnet Who-Is request (broadcast on the local network or unicast \
                          to --host) on UDP 47808 and collects I-Am responses to enumerate devices. \
                          For each discovered device the plugin probes common Device-object properties \
                          (vendor name, model, firmware revision, location, etc.) via unauthenticated \
                          ReadProperty requests. BACnet provides no authentication by default. A device \
                          that responds to Who-Is is flagged High severity. Successful ReadProperty \
                          access is flagged Critical.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "host",
                    short: Some('H'),
                    help: "Target host for unicast scan (omit to broadcast)",
                    value_name: "HOST",
                    default: Some(""),
                    is_flag: false
                },
                CliArg {
                    name: "port",
                    short: Some('p'),
                    help: "BACnet/IP UDP port",
                    value_name: "PORT",
                    default: Some("47808"),
                    is_flag: false
                },
                CliArg {
                    name: "timeout_ms",
                    short: None,
                    help: "Who-Is discovery window (ms)",
                    value_name: "MS",
                    default: Some("3000"),
                    is_flag: false
                },
                CliArg {
                    name: "device_id",
                    short: Some('I'),
                    help: "BACnet device instance number; skips Who-Is/I-Am discovery. \
                           Required when client and device share a host.",
                    value_name: "ID",
                    default: None,
                    is_flag: false,
                },
            ],
        )
    }

    /// Initialize the plugin with the given configuration.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        let host = config.get_or("host", "");
        self.host = if host.is_empty() { None } else { Some(host) };
        self.port = config.parse_or("port", BACNET_DEFAULT_PORT);
        self.timeout_ms = config.parse_or("timeout_ms", 3_000u64);
        self.device_id = config.get("device_id").and_then(|s| s.parse().ok());
        Ok(())
    }

    /// Execute the plugin's main logic.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let client = BacnetClient::builder()
            .timeout(Duration::from_millis(self.timeout_ms))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create BACnet client: {e}"))?;

        let devices = if let Some(id) = self.device_id {
            let host = self.host.as_deref()
                .ok_or_else(|| anyhow::anyhow!("--host is required when --device-id is set"))?;
            let addr: SocketAddr = format!("{}:{}", host, self.port)
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid host/port: {e}"))?;
            vec![super::connect(&client, addr, Some(id))?]
        } else if let Some(ref host) = self.host {
            let addr: SocketAddr = format!("{}:{}", host, self.port)
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid host/port: {e}"))?;
            client.who_is_to(addr, None, None)
                .map_err(|e| anyhow::anyhow!("who-is failed: {e}"))?
        } else {
            client.who_is(None, None)
                .map_err(|e| anyhow::anyhow!("who-is broadcast failed: {e}"))?
        };

        if devices.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No BACnet/IP devices found",
                format!(
                    "No I-Am responses received within {} ms. \
                     The target may not expose BACnet or UDP {} is firewalled.",
                    self.timeout_ms, self.port,
                ),
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        for device in &devices {
            let peer = device.address;
            let target = BacnetTarget::from(device);
            let oid = ObjectIdentifier::new(ObjectType::Device, device.device_id);

            let mut evidence = vec![
                format!("Address:         {peer}"),
                format!("Device instance: {}", device.device_id),
                format!("Vendor ID:       {}", device.vendor_id),
                format!("Vendor:          {}", device.vendor_name),
            ];

            let props: &[(PropertyIdentifier, &str)] = &[
                (PropertyIdentifier::ObjectName,                 "Object Name"),
                (PropertyIdentifier::ModelName,                  "Model Name"),
                (PropertyIdentifier::FirmwareRevision,           "Firmware Revision"),
                (PropertyIdentifier::ApplicationSoftwareVersion, "App Software Version"),
                (PropertyIdentifier::Description,                "Description"),
                (PropertyIdentifier::Location,                   "Location"),
            ];

            let mut readable: Vec<&str> = Vec::new();
            for (prop, prop_name) in props {
                if let Ok(values) = client.read_property(target.clone(), oid, prop.clone()) {
                    if let Some(val) = super::format_value(values) {
                        evidence.push(format!("{prop_name}: {val}"));
                        readable.push(prop_name);
                    }
                }
            }

            let (severity, title, description) = if readable.is_empty() {
                (
                    Severity::High,
                    format!("BACnet/IP device at {peer} (instance {})", device.device_id),
                    "Device responded to Who-Is/I-Am without authentication. \
                     ReadProperty queries were rejected or timed out."
                    .to_string(),
                )
            } else {
                (
                    Severity::Critical,
                    format!(
                        "BACnet/IP device at {peer} exposes {} propert{} unauthenticated",
                        readable.len(),
                        if readable.len() == 1 { "y" } else { "ies" }
                    ),
                    format!(
                        "Device accepted ReadProperty requests for {} Device-object propert{} \
                         without credentials: {}.",
                        readable.len(),
                        if readable.len() == 1 { "y" } else { "ies" },
                        readable.join(", ")
                    ),
                )
            };

            result.add(
                PluginFinding::new(severity, title, description)
                    .with_evidence(evidence.join("\n")),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(BacnetScanner::new()) as Box<dyn crate::Plugin>)
}
