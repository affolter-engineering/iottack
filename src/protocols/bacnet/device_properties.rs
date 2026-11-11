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

/// All standard Device object properties defined in ASHRAE 135.
fn all_device_props() -> Vec<(&'static str, PropertyIdentifier)> {
    vec![
        // Required properties
        ("Object Identifier",               PropertyIdentifier::ObjectIdentifier),
        ("Object Name",                     PropertyIdentifier::ObjectName),
        ("Object Type",                     PropertyIdentifier::ObjectType),
        ("System Status",                   PropertyIdentifier::SystemStatus),
        ("Vendor Name",                     PropertyIdentifier::VendorName),
        ("Vendor Identifier",               PropertyIdentifier::VendorIdentifier),
        ("Model Name",                      PropertyIdentifier::ModelName),
        ("Firmware Revision",               PropertyIdentifier::FirmwareRevision),
        ("Application Software Version",    PropertyIdentifier::ApplicationSoftwareVersion),
        ("Protocol Version",                PropertyIdentifier::ProtocolVersion),
        ("Protocol Revision",               PropertyIdentifier::ProtocolRevision),
        ("Protocol Services Supported",     PropertyIdentifier::ProtocolServicesSupported),
        ("Protocol Object Types Supported", PropertyIdentifier::ProtocolObjectTypesSupported),
        ("Object List",                     PropertyIdentifier::ObjectList),
        ("Max APDU Length Accepted",        PropertyIdentifier::MaxApduLengthAccepted),
        ("Segmentation Supported",          PropertyIdentifier::SegmentationSupported),
        ("APDU Timeout (ms)",               PropertyIdentifier::ApduTimeout),
        ("Number of APDU Retries",          PropertyIdentifier::NumberOfApduRetries),
        ("Database Revision",               PropertyIdentifier::DatabaseRevision),
        // Optional but common
        ("Description",                     PropertyIdentifier::Description),
        ("Location",                        PropertyIdentifier::Location),
        ("Local Date",                      PropertyIdentifier::LocalDate),
        ("Local Time",                      PropertyIdentifier::LocalTime),
        ("UTC Offset (min)",                PropertyIdentifier::UtcOffset),
        ("Daylight Savings Status",         PropertyIdentifier::DaylightSavingsStatus),
        ("Profile Name",                    PropertyIdentifier::ProfileName),
        ("Last Restart Reason",             PropertyIdentifier::LastRestartReason),
        ("Backup and Restore State",        PropertyIdentifier::BackupAndRestoreState),
        ("Out of Service",                  PropertyIdentifier::OutOfService),
        ("Event State",                     PropertyIdentifier::EventState),
        ("Status Flags",                    PropertyIdentifier::StatusFlags),
    ]
}

/// Enumerate all standard properties of the BACnet Device object.
pub struct DevicePropertiesPlugin {
    host: String,
    port: u16,
    timeout_ms: u64,
    device_id: Option<u32>,
}

/// Create a new instance of the DevicePropertiesPlugin with default settings.
impl DevicePropertiesPlugin {
    pub fn new() -> Self {
        Self { host: String::new(), port: BACNET_DEFAULT_PORT, timeout_ms: 5_000, device_id: None }
    }
}

/// Implement the Default trait for the DevicePropertiesPlugin, allowing it to be instantiated with default settings.
impl Default for DevicePropertiesPlugin {
    fn default() -> Self { Self::new() }
}

/// Implement the Plugin trait for the DevicePropertiesPlugin, enabling it to be used as a plugin within the framework.
impl Plugin for DevicePropertiesPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Enumerate all properties on the target BACnet Device object",
            description: "Reads every standard ASHRAE 135 property of the Device object on the \
                          target via unauthenticated ReadProperty requests. This is equivalent to \
                          BACteria device_properties(). The Device object is the root of a BACnet \
                          device's information model. Its properties expose configuration, \
                          capability and operational state. All readable properties are reported \
                          as Critical findings.",
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

    /// Execute the plugin logic, performing the BACnet device property enumeration and reporting findings.
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

        let mut lines: Vec<String> = Vec::new();
        let mut readable = 0usize;

        for (label, prop) in all_device_props() {
            match client.read_property(target.clone(), oid, prop) {
                Ok(values) => {
                    let display = super::format_value(values)
                        .unwrap_or_else(|| "<binary/complex>".into());
                    lines.push(format!("{label}: {display}"));
                    readable += 1;
                }
                Err(_) => {
                    lines.push(format!("{label}: <not readable>"));
                }
            }
        }

        if readable == 0 {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("No Device properties readable at {addr}"),
                "Device did not return any readable properties for the Device object."
                    .to_string(),
            ));
            result.finish(PluginStatus::Fail);
        } else {
            result.add(
                PluginFinding::new(
                    Severity::Critical,
                    format!(
                        "{readable} of {} Device propert{} readable unauthenticated at {addr}",
                        all_device_props().len(),
                        if readable == 1 { "y" } else { "ies" }
                    ),
                    format!(
                        "Unauthenticated ReadProperty returned {readable} Device-object properties \
                         from {addr} (device ID {}). This reveals configuration, capability, and \
                         operational state without credentials.",
                        device.device_id
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
    crate::PluginFactory(|| Box::new(DevicePropertiesPlugin::new()) as Box<dyn crate::Plugin>)
}
