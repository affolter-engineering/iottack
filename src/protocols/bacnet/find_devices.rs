use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use bacnet_rs::client::{BacnetClient, DeviceInfo};
use std::net::SocketAddr;
use std::time::Duration;

use super::BACNET_DEFAULT_PORT;

/// Discover BACnet devices and routers, no property reads, maximum speed.
pub struct FindDevicesPlugin {
    host: Option<String>,
    port: u16,
    timeout_ms: u64,
    network: Option<u16>,
    device_id: Option<u32>,
}

/// Implementation of the FindDevicesPlugin.
impl FindDevicesPlugin {
    pub fn new() -> Self {
        Self { host: None, port: BACNET_DEFAULT_PORT, timeout_ms: 3_000, network: None, device_id: None }
    }
}

/// Constructor for the FindDevicesPlugin.
impl Default for FindDevicesPlugin {
    fn default() -> Self { Self::new() }
}

/// Implementation of the Plugin trait for the FindDevicesPlugin.
impl Plugin for FindDevicesPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Enumerate BACnet devices and routers reachable from the current host",
            description: "Sends a BACnet Who-Is broadcast (or unicast to --host) and a \
                          Who-Is-Router broadcast to discover all BACnet devices and routers on \
                          the reachable network segment. Unlike bacnet/scan, no property reads \
                          are performed, making this a fast enumeration sweep. Pass --network to \
                          query for devices behind a specific router network number. \
                          Any discovered device or router is flagged High severity.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "host",
                    short: Some('H'),
                    help: "Unicast target (omit to broadcast)",
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
                    help: "Discovery window (ms)",
                    value_name: "MS",
                    default: Some("3000"),
                    is_flag: false
                },
                CliArg {
                    name: "network",
                    short: Some('n'),
                    help: "BACnet network number to query via router",
                    value_name: "NET",
                    default: Some(""),
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
        let net_str = config.get_or("network", "");
        self.network = if net_str.is_empty() {
            None
        } else {
            Some(net_str.parse::<u16>().map_err(|e| anyhow::anyhow!("invalid network number: {e}"))?)
        };
        self.device_id = config.get("device_id").and_then(|s| s.parse().ok());
        Ok(())
    }

    /// Execute the device discovery routine and return the results.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let client = BacnetClient::builder()
            .timeout(Duration::from_millis(self.timeout_ms))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create BACnet client: {e}"))?;

        // Device discovery
        let devices: Vec<DeviceInfo> = if let Some(id) = self.device_id {
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

            if let Some(net) = self.network {
                client.who_is_network(addr, net, None, None)
                    .map_err(|e| anyhow::anyhow!("who-is-network failed: {e}"))?
            } else {
                client.who_is_to(addr, None, None)
                    .map_err(|e| anyhow::anyhow!("who-is failed: {e}"))?
            }
        } else {
            client.who_is(None, None)
                .map_err(|e| anyhow::anyhow!("who-is broadcast failed: {e}"))?
        };

        if !devices.is_empty() {
            let lines: Vec<String> = devices.iter().map(|d| {
                let route = d.route.as_ref()
                    .map(|r| format!("  (routed via {:?})", r))
                    .unwrap_or_default();
                format!(
                    "{}  ID={}  vendor={} ({})  max-apdu={}{}",
                    d.address, d.device_id, d.vendor_name, d.vendor_id, d.max_apdu, route
                )
            }).collect();

            result.add(
                PluginFinding::new(
                    Severity::High,
                    format!("{} BACnet device{} found", devices.len(), if devices.len() == 1 { "" } else { "s" }),
                    format!(
                        "{} BACnet device{} responded to unauthenticated Who-Is. \
                         Use bacnet/scan for property enumeration or bacnet/object-list \
                         for full object model access.",
                        devices.len(),
                        if devices.len() == 1 { "" } else { "s" }
                    ),
                )
                .with_evidence(lines.join("\n")),
            );
        }

        // Router discovery
        let routers = if let Some(ref host) = self.host {
            let addr: SocketAddr = format!("{}:{}", host, self.port)
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid host/port: {e}"))?;
            client.who_is_router_to(addr, self.network)
                .unwrap_or_default()
        } else {
            client.who_is_router(self.network)
                .unwrap_or_default()
        };

        if !routers.is_empty() {
            let lines: Vec<String> = routers.iter().map(|r| {
                let nets: Vec<String> = r.networks.iter().map(|n| n.to_string()).collect();
                format!("{}  networks=[{}]", r.address, nets.join(", "))
            }).collect();

            result.add(
                PluginFinding::new(
                    Severity::High,
                    format!(
                        "{} BACnet router{} found",
                        routers.len(),
                        if routers.len() == 1 { "" } else { "s" }
                    ),
                    format!(
                        "{} BACnet router{} responded to Who-Is-Router, indicating downstream \
                         BACnet network segments that may contain additional devices.",
                        routers.len(),
                        if routers.len() == 1 { "" } else { "s" }
                    ),
                )
                .with_evidence(lines.join("\n")),
            );
        }

        if devices.is_empty() && routers.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No BACnet devices or routers found",
                format!(
                    "No I-Am or I-Am-Router-To-Network responses received within {} ms.",
                    self.timeout_ms
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
    crate::PluginFactory(|| Box::new(FindDevicesPlugin::new()) as Box<dyn crate::Plugin>)
}
