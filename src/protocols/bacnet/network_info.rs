use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use bacnet_rs::client::{BacnetClient, BacnetTarget};
use bacnet_rs::object::object_type::ObjectType;
use bacnet_rs::object::property_identifier::PropertyIdentifier;
use bacnet_rs::object::ObjectIdentifier;
use std::net::SocketAddr;
use std::time::Duration;

use super::BACNET_DEFAULT_PORT;

/// Properties read from Network Port objects (ASHRAE 135 clause 12.56).
fn network_port_props() -> Vec<(&'static str, PropertyIdentifier)> {
    vec![
        ("Object Name",             PropertyIdentifier::ObjectName),
        ("Description",             PropertyIdentifier::Description),
        ("Out of Service",          PropertyIdentifier::OutOfService),
        ("Network Type",            PropertyIdentifier::NetworkType),
        ("Protocol Level",          PropertyIdentifier::ProtocolLevel),
        ("Network Number",          PropertyIdentifier::NetworkNumber),
        ("Network Number Quality",  PropertyIdentifier::NetworkNumberQuality),
        ("Changes Pending",         PropertyIdentifier::ChangesPending),
        ("MAC Address",             PropertyIdentifier::MacAddress),
        ("IP Address",              PropertyIdentifier::IpAddress),
        ("IP Subnet Mask",          PropertyIdentifier::IpSubnetMask),
        ("IP Default Gateway",      PropertyIdentifier::IpDefaultGateway),
        ("IP DNS Server",           PropertyIdentifier::IpDnsServer),
        ("BACnet IP UDP Port",      PropertyIdentifier::BacnetIpUdpPort),
        ("BACnet IP NAT Traversal", PropertyIdentifier::BacnetIpNatTraversal),
        ("IP DHCP Enable",          PropertyIdentifier::IpDhcpEnable),
        ("IP DHCP Server",          PropertyIdentifier::IpDhcpServer),
        ("Link Speed",              PropertyIdentifier::LinkSpeed),
    ]
}

/// Show BACnet network topology: device addressing, Network Port objects, and discovered routers.
pub struct NetworkInfoPlugin {
    host: String,
    port: u16,
    timeout_ms: u64,
    device_id: Option<u32>,
}

/// Constructor for the NetworkInfoPlugin.
impl NetworkInfoPlugin {
    pub fn new() -> Self {
        Self { host: String::new(), port: BACNET_DEFAULT_PORT, timeout_ms: 5_000, device_id: None }
    }
}

/// Default implementation for the NetworkInfoPlugin.
impl Default for NetworkInfoPlugin {
    fn default() -> Self { Self::new() }
}

/// Implementation of the Plugin trait for the NetworkInfoPlugin.
impl Plugin for NetworkInfoPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Show BACnet network link details, addressing, and router topology",
            description: "Reads network-related information from a BACnet/IP device: device \
                          addressing from the I-Am response, Network Port object properties \
                          (IP address, subnet, gateway, UDP port, DHCP, MAC, link speed), and \
                          any BACnet routers advertised on the network via Who-Is-Router. \
                          Equivalent to BACteria network_info(). Exposed network topology is \
                          flagged High severity.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "host",
                    short: Some('H'),
                    help: "Target BACnet/IP device",
                    value_name: "HOST",
                    default: None,
                    is_flag: false,
                },
                CliArg {
                    name: "port",
                    short: Some('p'),
                    help: "BACnet/IP UDP port",
                    value_name: "PORT",
                    default: Some("47808"),
                    is_flag: false,
                },
                CliArg {
                    name: "timeout_ms",
                    short: None,
                    help: "Per-request timeout (ms)",
                    value_name: "MS",
                    default: Some("5000"),
                    is_flag: false,
                },
                CliArg {
                    name: "device_id",
                    short: Some('I'),
                    help: "BACnet device instance number. Skips Who-Is/I-Am discovery. \
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
        self.host = config.require("host")?.to_string();
        self.port = config.parse_or("port", BACNET_DEFAULT_PORT);
        self.timeout_ms = config.parse_or("timeout_ms", 5_000u64);
        self.device_id = config.get("device_id").and_then(|s| s.parse().ok());
        Ok(())
    }

    /// Execute the plugin's main logic.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid host/port: {e}"))?;

        let client = BacnetClient::builder()
            .timeout(Duration::from_millis(self.timeout_ms))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create BACnet client: {e}"))?;

        let device = super::connect(&client, addr, self.device_id)?;

        let target = BacnetTarget::from(&device);

        // Device addressing
        let mut addr_lines = vec![
            format!("UDP address:   {}", device.address),
            format!("Device ID:     {}", device.device_id),
            format!("Vendor:        {} (ID {})", device.vendor_name, device.vendor_id),
            format!("Max APDU:      {}", device.max_apdu),
            format!("Segmentation:  {:?}", device.segmentation),
        ];
        if let Some(ref route) = device.route {
            addr_lines.push(format!("Routed via:    {:?}", route));
        }

        result.add(
            PluginFinding::new(
                Severity::High,
                format!("BACnet device addressing exposed at {addr}"),
                "The device responded to unauthenticated Who-Is/I-Am, revealing its network \
                 address, device ID, vendor identity, and transport capabilities."
                    .to_string(),
            )
            .with_evidence(addr_lines.join("\n")),
        );

        // Network Port objects
        let net_port_objects: Vec<ObjectIdentifier> = client
            .read_object_list(target.clone(), device.device_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|o| o.object_type == ObjectType::NetworkPort)
            .collect();

        for np_id in &net_port_objects {
            let mut np_lines: Vec<String> = Vec::new();
            let mut readable = 0usize;

            for (label, prop) in network_port_props() {
                if let Ok(values) = client.read_property(target.clone(), *np_id, prop) {
                    if let Some(val) = super::format_value(values) {
                        np_lines.push(format!("{label}: {val}"));
                        readable += 1;
                    }
                }
            }

            if readable > 0 {
                result.add(
                    PluginFinding::new(
                        Severity::High,
                        format!(
                            "Network Port {:?}:{} exposes {readable} network properties at {addr}",
                            np_id.object_type, np_id.instance,
                        ),
                        format!(
                            "The Network Port object at instance {} was readable without \
                             credentials, revealing IP addressing, DHCP configuration, and \
                             link details.",
                            np_id.instance
                        ),
                    )
                    .with_evidence(np_lines.join("\n")),
                );
            }
        }

        // BACnet router discovery
        let routers = client
            .who_is_router_to(addr, None)
            .unwrap_or_default();

        if !routers.is_empty() {
            let router_lines: Vec<String> = routers.iter().map(|r| {
                let nets: Vec<String> = r.networks.iter().map(|n| n.to_string()).collect();
                format!("{} → networks [{}]", r.address, nets.join(", "))
            }).collect();

            result.add(
                PluginFinding::new(
                    Severity::High,
                    format!(
                        "{} BACnet router{} discovered from {addr}",
                        routers.len(),
                        if routers.len() == 1 { "" } else { "s" }
                    ),
                    format!(
                        "{} BACnet router{} responded to Who-Is-Router, advertising \
                         reachable BACnet networks. These routers can be used for \
                         lateral discovery of downstream devices.",
                        routers.len(),
                        if routers.len() == 1 { "" } else { "s" }
                    ),
                )
                .with_evidence(router_lines.join("\n")),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(NetworkInfoPlugin::new()) as Box<dyn crate::Plugin>)
}
