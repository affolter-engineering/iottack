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

const MAX_OBJECTS_DEFAULT: usize = 64;

/// Enumerate all BACnet objects on a device and read their names and present values.
pub struct ObjectListPlugin {
    host: String,
    port: u16,
    timeout_ms: u64,
    device_id: Option<u32>,
    max_objects: usize,
}

impl ObjectListPlugin {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: BACNET_DEFAULT_PORT,
            timeout_ms: 5_000,
            device_id: None,
            max_objects: MAX_OBJECTS_DEFAULT,
        }
    }
}

/// Default implementation for ObjectListPlugin
impl Default for ObjectListPlugin {
    fn default() -> Self { Self::new() }
}

/// Plugin implementation for ObjectListPlugin
impl Plugin for ObjectListPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Enumerate all BACnet objects on a device and read their present values",
            description: "Reads the object-list property (prop 76) of the target device to obtain \
                          every instantiated BACnet object, then reads the object-name (prop 77) \
                          and, for data-point types (Analog/Binary/Multi-State), the present-value \
                          (prop 85). \
                          Unauthenticated enumeration of process data is flagged Critical.",
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
                    name: "max_objects",
                    short: None,
                    help: "Cap on objects to enumerate",
                    value_name: "N",
                    default: Some("64"),
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
        self.max_objects = config.parse_or("max_objects", MAX_OBJECTS_DEFAULT);
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
        let device_oid = ObjectIdentifier::new(ObjectType::Device, device.device_id);

        let list_values = match client.read_property(
            target.clone(),
            device_oid,
            PropertyIdentifier::ObjectList,
        ) {
            Ok(v) => v,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Object list not readable",
                    format!(
                        "Device at {addr} did not return the object-list property: {e}. \
                         The device may not support ReadProperty or the list exceeds \
                         the maximum APDU size."
                    ),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        let mut objects: Vec<ObjectIdentifier> = list_values
            .into_iter()
            .filter_map(|v| {
                if let PropertyValue::ObjectIdentifier(oid) = v { Some(oid) } else { None }
            })
            .collect();

        if objects.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "Object list not readable",
                format!(
                    "Device at {addr} did not return the object-list property. \
                     The device may not support ReadProperty or the list exceeds \
                     the maximum APDU size."
                ),
            ));
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        let total = objects.len();
        let capped = objects.len().min(self.max_objects);
        objects.truncate(capped);

        let mut readable_values: Vec<String> = Vec::new();
        let mut object_lines: Vec<String> = Vec::new();

        for obj_id in &objects {
            let type_name = super::object_type_name(&obj_id.object_type);

            let name = client
                .read_property(target.clone(), *obj_id, PropertyIdentifier::ObjectName)
                .ok()
                .and_then(super::format_value);

            let pv = if super::is_data_point(&obj_id.object_type) {
                client
                    .read_property(target.clone(), *obj_id, PropertyIdentifier::PresentValue)
                    .ok()
                    .and_then(super::format_value)
            } else {
                None
            };

            let mut line = format!(
                "{type_name}:{}  name={}",
                obj_id.instance,
                name.as_deref().unwrap_or("<unreadable>")
            );
            if let Some(ref v) = pv {
                line.push_str(&format!("  present-value={v}"));
                readable_values.push(format!(
                    "{type_name}:{} = {v} ({})",
                    obj_id.instance,
                    name.as_deref().unwrap_or("?")
                ));
            }
            object_lines.push(line);
        }

        let truncation_note = if total > capped {
            format!(" (showing {capped} of {total}; use --max-objects to increase)")
        } else {
            String::new()
        };

        result.add(
            PluginFinding::new(
                Severity::High,
                format!("BACnet object list readable at {addr}: {total} objects{truncation_note}"),
                format!(
                    "Unauthenticated ReadProperty access returned {total} BACnet objects. \
                     Object enumeration reveals the full process model of the device."
                ),
            )
            .with_evidence(object_lines.join("\n")),
        );

        if !readable_values.is_empty() {
            result.add(
                PluginFinding::new(
                    Severity::Critical,
                    format!(
                        "{} process data-point{} readable unauthenticated at {addr}",
                        readable_values.len(),
                        if readable_values.len() == 1 { "" } else { "s" }
                    ),
                    format!(
                        "Present-value of {} data-point object{} was accessible without \
                         credentials. This exposes live sensor/actuator readings.",
                        readable_values.len(),
                        if readable_values.len() == 1 { "" } else { "s" }
                    ),
                )
                .with_evidence(readable_values.join("\n")),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(ObjectListPlugin::new()) as Box<dyn crate::Plugin>)
}
