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

/// Returns a list of basic identification and status properties for a BACnet device.
fn info_props() -> Vec<(&'static str, PropertyIdentifier)> {
    vec![
        ("Object Identifier",           PropertyIdentifier::ObjectIdentifier),
        ("Object Name",                  PropertyIdentifier::ObjectName),
        ("System Status",                PropertyIdentifier::SystemStatus),
        ("Vendor Name",                  PropertyIdentifier::VendorName),
        ("Vendor Identifier",            PropertyIdentifier::VendorIdentifier),
        ("Model Name",                   PropertyIdentifier::ModelName),
        ("Firmware Revision",            PropertyIdentifier::FirmwareRevision),
        ("Application Software Version", PropertyIdentifier::ApplicationSoftwareVersion),
        ("Description",                  PropertyIdentifier::Description),
        ("Location",                     PropertyIdentifier::Location),
        ("Protocol Version",             PropertyIdentifier::ProtocolVersion),
        ("Protocol Revision",            PropertyIdentifier::ProtocolRevision),
        ("Max APDU Length Accepted",     PropertyIdentifier::MaxApduLengthAccepted),
        ("Segmentation Supported",       PropertyIdentifier::SegmentationSupported),
        ("APDU Timeout (ms)",            PropertyIdentifier::ApduTimeout),
        ("APDU Retries",                 PropertyIdentifier::NumberOfApduRetries),
        ("Database Revision",            PropertyIdentifier::DatabaseRevision),
        ("Last Restart Reason",          PropertyIdentifier::LastRestartReason),
        ("Backup and Restore State",     PropertyIdentifier::BackupAndRestoreState),
        ("Local Date",                   PropertyIdentifier::LocalDate),
        ("Local Time",                   PropertyIdentifier::LocalTime),
        ("UTC Offset (min)",             PropertyIdentifier::UtcOffset),
        ("Daylight Savings",             PropertyIdentifier::DaylightSavingsStatus),
        ("Profile Name",                 PropertyIdentifier::ProfileName),
    ]
}

/// Read basic identification and status properties from a BACnet/IP device.
pub struct InfoPlugin {
    host: String,
    port: u16,
    timeout_ms: u64,
    device_id: Option<u32>,
}

impl InfoPlugin {
    pub fn new() -> Self {
        Self { host: String::new(), port: BACNET_DEFAULT_PORT, timeout_ms: 5_000, device_id: None }
    }
}

impl Default for InfoPlugin {
    fn default() -> Self { Self::new() }
}

impl Plugin for InfoPlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Show basic identification and status properties of a BACnet/IP device",
            description: "Connects to a specific BACnet/IP device and reads a curated set of \
                          Device-object properties: vendor, model, firmware, software version, \
                          location, protocol version, APDU settings, system status, local clock, \
                          and backup/restore state. \
                          All reads are unauthenticated; any readable identifying information is \
                          flagged Critical.",
            needs_root: false,
            args: &[
                CliArg { name: "host",       short: Some('H'), help: "Target BACnet/IP device",  value_name: "HOST", default: None,         is_flag: false },
                CliArg { name: "port",       short: Some('p'), help: "BACnet/IP UDP port",        value_name: "PORT", default: Some("47808"), is_flag: false },
                CliArg { name: "timeout_ms", short: None,      help: "Per-request timeout (ms)",  value_name: "MS",   default: Some("5000"),  is_flag: false },
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

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.host = config.require("host")?.to_string();
        self.port = config.parse_or("port", BACNET_DEFAULT_PORT);
        self.timeout_ms = config.parse_or("timeout_ms", 5_000u64);
        self.device_id = config.get("device_id").and_then(|s| s.parse().ok());
        Ok(())
    }

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

        let mut lines: Vec<String> = vec![
            format!("Address:    {}", device.address),
            format!("Device ID:  {}", device.device_id),
            format!("Vendor ID:  {} ({})", device.vendor_id, device.vendor_name),
            format!("Max APDU:   {}", device.max_apdu),
        ];

        let mut readable = 0usize;
        for (label, prop) in info_props() {
            if let Ok(values) = client.read_property(target.clone(), oid, prop) {
                if let Some(val) = super::format_value(values) {
                    lines.push(format!("{label}: {val}"));
                    readable += 1;
                }
            }
        }

        if readable == 0 {
            result.add(PluginFinding::new(
                Severity::High,
                format!("BACnet device found at {addr} (ID {})", device.device_id),
                "Device responded to Who-Is/I-Am but all Device-object properties were \
                 unreadable or timed out."
                .to_string(),
            ).with_evidence(lines.join("\n")));
            result.finish(PluginStatus::Fail);
        } else {
            result.add(PluginFinding::new(
                Severity::Critical,
                format!(
                    "{readable} device propert{} readable unauthenticated at {addr}",
                    if readable == 1 { "y" } else { "ies" }
                ),
                format!(
                    "Device at {addr} (ID {}) exposed {readable} identifying propert{} without \
                     credentials, revealing vendor, firmware, model, and operational details.",
                    device.device_id,
                    if readable == 1 { "y" } else { "ies" }
                ),
            ).with_evidence(lines.join("\n")));
            result.finish(PluginStatus::Pass);
        }

        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(InfoPlugin::new()) as Box<dyn crate::Plugin>)
}
