use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use bacnet_rs::client::{BacnetClient, BacnetTarget};
use bacnet_rs::object::object_type::ObjectType;
use bacnet_rs::object::property_identifier::PropertyIdentifier;
use bacnet_rs::object::ObjectIdentifier;
use bacnet_rs::property::PropertyValue;
use std::net::SocketAddr;
use std::time::Duration;

use super::BACNET_DEFAULT_PORT;

// Service name table (ASHRAE 135, services-supported bit positions)
const SERVICES: &[(usize, &str)] = &[
    (0,  "acknowledge-alarm"),
    (1,  "confirmed-cov-notification"),
    (2,  "confirmed-event-notification"),
    (3,  "get-alarm-summary"),
    (4,  "get-enrollment-summary"),
    (5,  "subscribe-cov"),
    (6,  "atomic-read-file"),
    (7,  "atomic-write-file"),
    (8,  "add-list-element"),
    (9,  "remove-list-element"),
    (10, "create-object"),
    (11, "delete-object"),
    (12, "read-property"),
    (13, "read-property-conditional"),
    (14, "read-property-multiple"),
    (15, "write-property"),
    (16, "write-property-multiple"),
    (17, "device-communication-control"),
    (18, "confirmed-private-transfer"),
    (19, "confirmed-text-message"),
    (20, "reinitialize-device"),
    (21, "vt-open"),
    (22, "vt-close"),
    (23, "vt-data"),
    (24, "authenticate"),
    (25, "request-key"),
    (26, "i-am"),
    (27, "i-have"),
    (28, "unconfirmed-cov-notification"),
    (29, "unconfirmed-event-notification"),
    (30, "unconfirmed-private-transfer"),
    (31, "unconfirmed-text-message"),
    (32, "time-synchronization"),
    (33, "who-has"),
    (34, "who-is"),
    (35, "read-range"),
    (36, "utc-time-synchronization"),
    (37, "life-safety-operation"),
    (38, "subscribe-cov-property"),
    (39, "get-event-information"),
    (40, "write-group"),
];

// Services that represent significant unauthenticated attack surface.
const DANGEROUS_SERVICES: &[(usize, &str)] = &[
    (10, "create-object                - can create new BACnet objects on the device"),
    (11, "delete-object                - can delete BACnet objects from the device"),
    (15, "write-property               - can modify device properties and control outputs"),
    (16, "write-property-multiple      - can modify multiple properties in a single request"),
    (17, "device-communication-control - can disable device communications (DoS)"),
    (20, "reinitialize-device          - can restart or factory-reset the device"),
];

// Object type name table (object-types-supported bit positions)
const OBJECT_TYPES: &[(usize, &str)] = &[
    (0,  "Analog-Input"),
    (1,  "Analog-Output"),
    (2,  "Analog-Value"),
    (3,  "Binary-Input"),
    (4,  "Binary-Output"),
    (5,  "Binary-Value"),
    (6,  "Calendar"),
    (7,  "Command"),
    (8,  "Device"),
    (9,  "Event-Enrollment"),
    (10, "File"),
    (11, "Group"),
    (12, "Loop"),
    (13, "Multi-State-Input"),
    (14, "Multi-State-Output"),
    (15, "Notification-Class"),
    (16, "Program"),
    (17, "Schedule"),
    (18, "Averaging"),
    (19, "Multi-State-Value"),
    (20, "Trend-Log"),
    (21, "Life-Safety-Point"),
    (22, "Life-Safety-Zone"),
    (23, "Accumulator"),
    (24, "Pulse-Converter"),
    (25, "Event-Log"),
    (28, "Trend-Log-Multiple"),
    (29, "Load-Control"),
    (30, "Structured-View"),
    (31, "Access-Door"),
    (36, "Access-Zone"),
    (37, "Access-User"),
    (38, "Access-Rights"),
    (39, "Access-Credential"),
    (40, "Access-Point"),
];

/// Read the services-supported and object-types-supported BitStrings to fingerprint
/// device capabilities and flag dangerous unauthenticated service exposure.
pub struct ServicesPlugin {
    host: String,
    port: u16,
    timeout_ms: u64,
    device_id: Option<u32>,
}

/// ServicesPlugin implementation
impl ServicesPlugin {
    pub fn new() -> Self {
        Self { host: String::new(), port: BACNET_DEFAULT_PORT, timeout_ms: 5_000, device_id: None }
    }

    fn resolve_bits<'a>(bits: &[bool], table: &'a [(usize, &str)]) -> Vec<&'a str> {
        table.iter()
            .filter(|(bit, _)| bits.get(*bit).copied().unwrap_or(false))
            .map(|(_, name)| *name)
            .collect()
    }

    fn extract_bitstring(values: Vec<PropertyValue>) -> Option<Vec<bool>> {
        match values.into_iter().next()? {
            PropertyValue::BitString(bits) => Some(bits),
            _ => None,
        }
    }
}

/// Default implementation for ServicesPlugin
impl Default for ServicesPlugin {
    fn default() -> Self { Self::new() }
}

/// Plugin implementation for ServicesPlugin
impl Plugin for ServicesPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Read BACnet services-supported and object-types-supported from a device",
            description: "Reads the services-supported BitString (prop 97) and \
                          object-types-supported BitString (prop 96) from the Device object \
                          via unauthenticated ReadProperty. These properties reveal the full \
                          capability set of the device.Dangerous services \
                          (write-property, device-communication-control, reinitialize-device, \
                          etc.) are flagged High severity.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "host",
                    short: Some('H'),
                    help: "Target BACnet/IP device",
                    value_name: "HOST",
                    default: None,
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
                    help: "Per-request timeout (ms)",
                    value_name: "MS",
                    default: Some("5000"),
                    is_flag: false
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
        let oid = ObjectIdentifier::new(ObjectType::Device, device.device_id);

        let mut found_anything = false;

        // Services supported.
        if let Some(svc_bits) = client
            .read_property(target.clone(), oid, PropertyIdentifier::ProtocolServicesSupported)
            .ok()
            .and_then(Self::extract_bitstring)
        {
            found_anything = true;
            let enabled = Self::resolve_bits(&svc_bits, SERVICES);

            result.add(
                PluginFinding::new(
                    Severity::Medium,
                    format!("{} BACnet services readable unauthenticated at {addr}", enabled.len()),
                    format!(
                        "The services-supported property was readable without credentials, \
                         revealing the complete service capability set ({} services).",
                        enabled.len()
                    ),
                )
                .with_evidence(enabled.join("\n")),
            );

            let dangerous: Vec<&str> = DANGEROUS_SERVICES.iter()
                .filter(|(bit, _)| svc_bits.get(*bit).copied().unwrap_or(false))
                .map(|(_, desc)| *desc)
                .collect();

            if !dangerous.is_empty() {
                result.add(
                    PluginFinding::new(
                        Severity::High,
                        format!(
                            "{} dangerous service{} enabled at {addr}",
                            dangerous.len(),
                            if dangerous.len() == 1 { "" } else { "s" }
                        ),
                        format!(
                            "The following {} service{} allow unauthenticated modification \
                             or disruption of device operation:",
                            dangerous.len(),
                            if dangerous.len() == 1 { "" } else { "s" }
                        ),
                    )
                    .with_evidence(dangerous.join("\n")),
                );
            }
        }

        // Object types supported.
        if let Some(type_bits) = client
            .read_property(target.clone(), oid, PropertyIdentifier::ProtocolObjectTypesSupported)
            .ok()
            .and_then(Self::extract_bitstring)
        {
            found_anything = true;
            let types = Self::resolve_bits(&type_bits, OBJECT_TYPES);

            result.add(
                PluginFinding::new(
                    Severity::Info,
                    format!("{} BACnet object types supported at {addr}", types.len()),
                    format!(
                        "The object-types-supported property was readable unauthenticated, \
                         revealing the supported object model ({} types).",
                        types.len()
                    ),
                )
                .with_evidence(types.join("\n")),
            );
        }

        if !found_anything {
            result.add(PluginFinding::new(
                Severity::Info,
                "Services/object-type properties not readable",
                format!(
                    "Device at {addr} did not return services-supported or \
                     object-types-supported within {} ms.",
                    self.timeout_ms,
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
    crate::PluginFactory(|| Box::new(ServicesPlugin::new()) as Box<dyn crate::Plugin>)
}
