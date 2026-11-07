use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use bacnet_rs::client::{BacnetClient, BacnetTarget};
use bacnet_rs::object::property_identifier::PropertyIdentifier;
use bacnet_rs::object::ObjectIdentifier;
use std::net::SocketAddr;
use std::time::Duration;

use super::BACNET_DEFAULT_PORT;

/// Standard properties tried on every object type.
fn common_props() -> Vec<(&'static str, PropertyIdentifier)> {
    vec![
        ("Object Identifier",   PropertyIdentifier::ObjectIdentifier),
        ("Object Name",         PropertyIdentifier::ObjectName),
        ("Object Type",         PropertyIdentifier::ObjectType),
        ("Description",         PropertyIdentifier::Description),
        ("Present Value",       PropertyIdentifier::PresentValue),
        ("Status Flags",        PropertyIdentifier::StatusFlags),
        ("Event State",         PropertyIdentifier::EventState),
        ("Out of Service",      PropertyIdentifier::OutOfService),
        ("Reliability",         PropertyIdentifier::Reliability),
        ("Units",               PropertyIdentifier::Units),
        ("Min Pres Value",      PropertyIdentifier::MinPresValue),
        ("Max Pres Value",      PropertyIdentifier::MaxPresValue),
        ("Resolution",          PropertyIdentifier::Resolution),
        ("COV Increment",       PropertyIdentifier::CovIncrement),
        ("High Limit",          PropertyIdentifier::HighLimit),
        ("Low Limit",           PropertyIdentifier::LowLimit),
        ("Deadband",            PropertyIdentifier::Deadband),
        ("Limit Enable",        PropertyIdentifier::LimitEnable),
        ("Event Enable",        PropertyIdentifier::EventEnable),
        ("Acked Transitions",   PropertyIdentifier::AckedTransitions),
        ("Notify Type",         PropertyIdentifier::NotifyType),
        ("Number of States",    PropertyIdentifier::NumberOfStates),
        ("State Text",          PropertyIdentifier::StateText),
        ("Active Text",         PropertyIdentifier::ActiveText),
        ("Inactive Text",       PropertyIdentifier::InactiveText),
        ("Polarity",            PropertyIdentifier::Polarity),
        ("Priority Array",      PropertyIdentifier::PriorityArray),
        ("Relinquish Default",  PropertyIdentifier::RelinquishDefault),
        ("Profile Name",        PropertyIdentifier::ProfileName),
        ("Property List",       PropertyIdentifier::PropertyList),
    ]
}

/// Parse "analogInput:1", "Analog-Input:1", "ai:1" into ObjectIdentifier.
fn parse_object(s: &str) -> anyhow::Result<ObjectIdentifier> {
    let (type_str, inst_str) = s.rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("expected TYPE:INSTANCE format, e.g. analogInput:1"))?;
    let instance = inst_str.trim().parse::<u32>()
        .map_err(|e| anyhow::anyhow!("invalid instance number: {e}"))?;
    let obj_type = super::parse_object_type(type_str.trim())
        .ok_or_else(|| anyhow::anyhow!(
            "unknown object type '{}'; try analogInput, binaryOutput, device, etc.", type_str
        ))?;
    Ok(ObjectIdentifier::new(obj_type, instance))
}

/// Read all discoverable properties of a specific BACnet object.
pub struct ObjectPropertiesPlugin {
    host: String,
    port: u16,
    timeout_ms: u64,
    device_id: Option<u32>,
    object: String,
}

impl ObjectPropertiesPlugin {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: BACNET_DEFAULT_PORT,
            timeout_ms: 5_000,
            device_id: None,
            object: String::new(),
        }
    }
}

impl Default for ObjectPropertiesPlugin {
    fn default() -> Self { Self::new() }
}

impl Plugin for ObjectPropertiesPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Show all readable properties of a specific BACnet object",
            description: "Reads all standard properties of the named BACnet object on the target \
                          device. The object is specified as TYPE:INSTANCE, e.g., analogInput:1 or \
                          binaryOutput:0. Common abbreviations (ai, ao, bi, bo, av, bv, msv, \
                          dev, etc.) are accepted. \
                          Any readable property on a process-data object is flagged High severity.",
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
                    name: "object",
                    short: Some('O'),
                    help: "Object to inspect (TYPE:INSTANCE, e.g., analogInput:1)",
                    value_name: "OBJ",
                    default: None,
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

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.require("host")?.to_string();
        self.port = config.parse_or("port", BACNET_DEFAULT_PORT);
        self.timeout_ms = config.parse_or("timeout_ms", 5_000u64);
        self.device_id = config.get("device_id").and_then(|s| s.parse().ok());
        self.object = config.require("object")?.to_string();
        Ok(())
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid host/port: {e}"))?;

        let obj_id = parse_object(&self.object)?;

        let client = BacnetClient::builder()
            .timeout(Duration::from_millis(self.timeout_ms))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create BACnet client: {e}"))?;

        let device = super::connect(&client, addr, self.device_id)?;

        let target = BacnetTarget::from(&device);

        let mut lines: Vec<String> = Vec::new();
        let mut readable = 0usize;

        for (label, prop) in common_props() {
            match client.read_property(target.clone(), obj_id, prop) {
                Ok(values) => {
                    let display = super::format_value(values)
                        .unwrap_or_else(|| "<binary/complex>".into());
                    lines.push(format!("{label}: {display}"));
                    readable += 1;
                }
                Err(_) => {}
            }
        }

        let obj_label = format!("{:?}:{}", obj_id.object_type, obj_id.instance);

        if lines.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No properties readable for {obj_label} at {addr}"),
                "All property reads timed out or were rejected.".to_string(),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            result.add(
                PluginFinding::new(
                    Severity::High,
                    format!(
                        "{readable} propert{} readable for {obj_label} at {addr}",
                        if readable == 1 { "y" } else { "ies" }
                    ),
                    format!(
                        "Unauthenticated ReadProperty returned {readable} propert{} of \
                         {obj_label} at {addr}.",
                        if readable == 1 { "y" } else { "ies" }
                    ),
                )
                .with_evidence(lines.join("\n")),
            );
            result.finish(PluginStatus::Pass);
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(ObjectPropertiesPlugin::new()) as Box<dyn crate::Plugin>)
}
