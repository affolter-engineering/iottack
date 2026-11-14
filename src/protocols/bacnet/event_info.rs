use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use bacnet_rs::client::{BacnetClient, BacnetTarget};
use bacnet_rs::object::object_type::ObjectType;
use bacnet_rs::object::property_identifier::PropertyIdentifier;
use bacnet_rs::property::PropertyValue;
use std::net::SocketAddr;
use std::time::Duration;

use super::BACNET_DEFAULT_PORT;

/// Convert an event state numeric value to its human-readable label.
fn event_state_name(n: u32) -> &'static str {
    match n {
        0 => "Normal",
        1 => "Fault",
        2 => "Offnormal",
        3 => "High-Limit",
        4 => "Low-Limit",
        5 => "Life-Safety-Alarm",
        _ => "Unknown",
    }
}

/// Convert an ObjectType to its human-readable label.
fn object_type_label(t: &ObjectType) -> &'static str {
    match t {
        ObjectType::AnalogInput => "Analog-Input",
        ObjectType::AnalogOutput => "Analog-Output",
        ObjectType::AnalogValue => "Analog-Value",
        ObjectType::BinaryInput => "Binary-Input",
        ObjectType::BinaryOutput => "Binary-Output",
        ObjectType::BinaryValue => "Binary-Value",
        ObjectType::MultiStateInput => "Multi-State-Input",
        ObjectType::MultiStateOutput => "Multi-State-Output",
        ObjectType::MultiStateValue => "Multi-State-Value",
        ObjectType::LifeSafetyPoint => "Life-Safety-Point",
        ObjectType::LifeSafetyZone => "Life-Safety-Zone",
        ObjectType::Loop => "Loop",
        ObjectType::Program => "Program",
        ObjectType::EventEnrollment => "Event-Enrollment",
        _ => "Object",
    }
}

/// List BACnet objects with non-normal event states.
pub struct EventInfoPlugin {
    host: String,
    port: u16,
    timeout_ms: u64,
    device_id: Option<u32>,
    max_objects: usize,
}

/// Create a new instance of the EventInfoPlugin with default settings.
impl EventInfoPlugin {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: BACNET_DEFAULT_PORT,
            timeout_ms: 5_000,
            device_id: None,
            max_objects: 128,
        }
    }
}

/// Implement the Default trait for the EventInfoPlugin, allowing it to be instantiated with default settings.
impl Default for EventInfoPlugin {
    fn default() -> Self { Self::new() }
}

/// Implement the Plugin trait for the EventInfoPlugin, enabling it to be used as a plugin within the framework.
impl Plugin for EventInfoPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "List currently active (non-normal) event states on a BACnet device",
            description: "Retrieves the object list from the target device and checks the \
                          event-state property (prop 36) on each object. Any object in a \
                          non-Normal state (Fault, Offnormal, High-Limit, Low-Limit, \
                          Life-Safety-Alarm) is reported. Objects in Normal state or without \
                          event-state support are silently skipped. \
                          Active alarms or faults are flagged Critical. A device where event \
                          states are readable is flagged High.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "host",
                    short: Some('H'),
                    help: "Target BACnet/IP device",
                    value_name: "HOST", default: None,
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
                    name: "max_objects",
                    short: None,
                    help: "Max objects to scan",
                    value_name: "N",
                    default: Some("128"),
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
        self.max_objects = config.parse_or("max_objects", 128usize);
        Ok(())
    }

    /// Execute the plugin logic and return the results.
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

        // Fetch object list
        let mut objects = client
            .read_object_list(target.clone(), device.device_id)
            .map_err(|e| anyhow::anyhow!("could not read object list: {e}"))?;

        if objects.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "Object list not readable",
                format!("Device at {addr} did not return the object list."),
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }
        objects.truncate(self.max_objects);

        // Check EventState on each object
        let mut active: Vec<String> = Vec::new();
        let mut normal_count = 0usize;
        let mut readable_count = 0usize;

        for obj_id in &objects {
            let Ok(values) = client.read_property(
                target.clone(),
                *obj_id,
                PropertyIdentifier::EventState,
            ) else {
                continue; // object doesn't support event-state
            };

            if let Some(PropertyValue::Enumerated(state)) = values.into_iter().next() {
                readable_count += 1;
                if state == 0 {
                    normal_count += 1;
                } else {
                    let label = format!(
                        "{}:{}  state={}",
                        object_type_label(&obj_id.object_type),
                        obj_id.instance,
                        event_state_name(state)
                    );
                    // Try to get object name for context
                    let name = client
                        .read_property(target.clone(), *obj_id, PropertyIdentifier::ObjectName)
                        .ok()
                        .and_then(super::format_value);
                    let line = if let Some(n) = name {
                        format!("{label}  ({n})")
                    } else {
                        label
                    };
                    active.push(line);
                }
            }
        }

        if readable_count == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                "Event states not readable",
                format!(
                    "None of the {} objects at {addr} supported unauthenticated \
                     event-state reads.",
                    objects.len()
                ),
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        // Event states were readable — always a finding
        result.add(PluginFinding::new(
            Severity::High,
            format!(
                "Event state readable on {readable_count} objects at {addr} \
                 ({normal_count} normal, {} active)",
                active.len()
            ),
            format!(
                "The event-state property was readable without credentials on {readable_count} \
                 objects at {addr}, revealing live alarm and fault conditions."
            ),
        ));

        if active.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No active events on {addr}"),
                format!(
                    "All {readable_count} objects with readable event-state report Normal state."
                ),
            ));
        } else {
            // Check for fault-severity conditions
            let has_faults = active.iter().any(|l| l.contains("Fault") || l.contains("Life-Safety"));
            result.add(
                PluginFinding::new(
                    if has_faults { Severity::Critical } else { Severity::High },
                    format!(
                        "{} active event{} on {addr}",
                        active.len(),
                        if active.len() == 1 { "" } else { "s" }
                    ),
                    format!(
                        "{} object{} are in a non-Normal event state, indicating active alarms \
                         or faults.",
                        active.len(),
                        if active.len() == 1 { "" } else { "s" }
                    ),
                )
                .with_evidence(active.join("\n")),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(EventInfoPlugin::new()) as Box<dyn crate::Plugin>)
}
