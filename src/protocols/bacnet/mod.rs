pub mod device_properties;
pub mod event_info;
pub mod find_devices;
pub mod fuzz;
pub mod info;
pub mod network_info;
pub mod object_list;
pub mod object_properties;
pub mod scan;
pub mod services;

pub(crate) const BACNET_DEFAULT_PORT: u16 = 47808; // 0xBAC0

use bacnet_rs::client::{BacnetClient, DeviceInfo};
use bacnet_rs::object::object_type::ObjectType;
use bacnet_rs::object::Segmentation;
use bacnet_rs::property::PropertyValue;
use std::net::SocketAddr;

/// Connect to a BACnet device.
///
/// When `device_id` is `Some`, discovery is skipped entirely and a `DeviceInfo`
/// is constructed directly from the address and instance number. This is needed
/// when the client and simulator share a host: the client socket is on a random
/// port and cannot receive I-Am broadcasts that the device sends to port 47808.
///
/// When `device_id` is `None`, a unicast Who-Is is sent and the first I-Am
/// response is returned. `who_is_to` (not `discover_device`) is used because
/// some implementations broadcast the I-Am response rather than sending it
/// unicast back to the requester.
pub(crate) fn connect(
    client: &BacnetClient,
    addr: SocketAddr,
    device_id: Option<u32>,
) -> anyhow::Result<DeviceInfo> {
    if let Some(id) = device_id {
        return Ok(DeviceInfo {
            device_id: id,
            address: addr,
            route: None,
            vendor_id: 0,
            vendor_name: String::new(),
            max_apdu: 1476,
            segmentation: Segmentation::NoSegmentation,
        });
    }
    client
        .who_is_to(addr, None, None)
        .map_err(|e| anyhow::anyhow!("device not found at {addr}: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!(
            "device not found at {addr}: no I-Am response \
             (try --device-id if the client and device share a host)"
        ))
}

pub(crate) fn object_type_name(obj_type: &ObjectType) -> &'static str {
    match obj_type {
        ObjectType::AnalogInput => "Analog-Input",
        ObjectType::AnalogOutput => "Analog-Output",
        ObjectType::AnalogValue => "Analog-Value",
        ObjectType::BinaryInput => "Binary-Input",
        ObjectType::BinaryOutput => "Binary-Output",
        ObjectType::BinaryValue => "Binary-Value",
        ObjectType::Calendar => "Calendar",
        ObjectType::Command => "Command",
        ObjectType::Device => "Device",
        ObjectType::EventEnrollment => "Event-Enrollment",
        ObjectType::File => "File",
        ObjectType::Group => "Group",
        ObjectType::Loop => "Loop",
        ObjectType::MultiStateInput => "Multi-State-Input",
        ObjectType::MultiStateOutput => "Multi-State-Output",
        ObjectType::NotificationClass => "Notification-Class",
        ObjectType::Program => "Program",
        ObjectType::Schedule => "Schedule",
        ObjectType::Averaging => "Averaging",
        ObjectType::MultiStateValue => "Multi-State-Value",
        ObjectType::TrendLog => "Trend-Log",
        ObjectType::LifeSafetyPoint => "Life-Safety-Point",
        ObjectType::LifeSafetyZone => "Life-Safety-Zone",
        ObjectType::Accumulator => "Accumulator",
        ObjectType::PulseConverter => "Pulse-Converter",
        ObjectType::EventLog => "Event-Log",
        ObjectType::TrendLogMultiple => "Trend-Log-Multiple",
        ObjectType::LoadControl => "Load-Control",
        ObjectType::StructuredView => "Structured-View",
        ObjectType::AccessDoor => "Access-Door",
        ObjectType::AccessZone => "Access-Zone",
        ObjectType::AccessUser => "Access-User",
        ObjectType::AccessRights => "Access-Rights",
        ObjectType::AccessCredential => "Access-Credential",
        ObjectType::AccessPoint => "Access-Point",
        ObjectType::NetworkPort => "Network-Port",
        _ => "Unknown",
    }
}

pub(crate) fn is_data_point(obj_type: &ObjectType) -> bool {
    matches!(
        obj_type,
        ObjectType::AnalogInput
            | ObjectType::AnalogOutput
            | ObjectType::AnalogValue
            | ObjectType::BinaryInput
            | ObjectType::BinaryOutput
            | ObjectType::BinaryValue
            | ObjectType::MultiStateInput
            | ObjectType::MultiStateOutput
            | ObjectType::MultiStateValue
    )
}

pub(crate) fn parse_object_type(s: &str) -> Option<ObjectType> {
    match s.to_lowercase().replace(['-', '_', ' '], "").as_str() {
        "analoginput"      | "ai"  => Some(ObjectType::AnalogInput),
        "analogoutput"     | "ao"  => Some(ObjectType::AnalogOutput),
        "analogvalue"      | "av"  => Some(ObjectType::AnalogValue),
        "binaryinput"      | "bi"  => Some(ObjectType::BinaryInput),
        "binaryoutput"     | "bo"  => Some(ObjectType::BinaryOutput),
        "binaryvalue"      | "bv"  => Some(ObjectType::BinaryValue),
        "calendar"                 => Some(ObjectType::Calendar),
        "command"                  => Some(ObjectType::Command),
        "device"           | "dev" => Some(ObjectType::Device),
        "eventenrollment"  | "ee"  => Some(ObjectType::EventEnrollment),
        "file"                     => Some(ObjectType::File),
        "group"                    => Some(ObjectType::Group),
        "loop"                     => Some(ObjectType::Loop),
        "multistateinput"  | "msi" => Some(ObjectType::MultiStateInput),
        "multistateoutput" | "mso" => Some(ObjectType::MultiStateOutput),
        "multistatevalue"  | "msv" => Some(ObjectType::MultiStateValue),
        "notificationclass"| "nc"  => Some(ObjectType::NotificationClass),
        "program"                  => Some(ObjectType::Program),
        "schedule"                 => Some(ObjectType::Schedule),
        "averaging"                => Some(ObjectType::Averaging),
        "trendlog"         | "tl"  => Some(ObjectType::TrendLog),
        "lifesafetypoint"  | "lsp" => Some(ObjectType::LifeSafetyPoint),
        "lifesafetyzone"   | "lsz" => Some(ObjectType::LifeSafetyZone),
        "accumulator"              => Some(ObjectType::Accumulator),
        "pulseconverter"   | "pc"  => Some(ObjectType::PulseConverter),
        "eventlog"         | "el"  => Some(ObjectType::EventLog),
        "trendlogmultiple" | "tlm" => Some(ObjectType::TrendLogMultiple),
        "loadcontrol"      | "lc"  => Some(ObjectType::LoadControl),
        "structuredview"   | "sv"  => Some(ObjectType::StructuredView),
        "accessdoor"       | "ad"  => Some(ObjectType::AccessDoor),
        "accesszone"       | "az"  => Some(ObjectType::AccessZone),
        "accessuser"       | "au"  => Some(ObjectType::AccessUser),
        "accessrights"     | "ar"  => Some(ObjectType::AccessRights),
        "accesscredential" | "ac"  => Some(ObjectType::AccessCredential),
        "accesspoint"      | "ap"  => Some(ObjectType::AccessPoint),
        "networkport"      | "np"  => Some(ObjectType::NetworkPort),
        _ => None,
    }
}

/// Format the first element of a `read_property` result as a display string.
pub(crate) fn format_value(values: Vec<PropertyValue>) -> Option<String> {
    match values.into_iter().next()? {
        PropertyValue::CharacterString(s) => Some(s),
        PropertyValue::Unsigned(n) => Some(n.to_string()),
        PropertyValue::Signed(n) => Some(n.to_string()),
        PropertyValue::Real(f) => Some(format!("{f:.4}")),
        PropertyValue::Double(f) => Some(format!("{f:.6}")),
        PropertyValue::Boolean(b) => Some(if b { "true" } else { "false" }.into()),
        PropertyValue::Enumerated(n) => Some(n.to_string()),
        PropertyValue::ObjectIdentifier(oid) => {
            Some(format!("{:?}:{}", oid.object_type, oid.instance))
        }
        PropertyValue::Date(year, month, day, _) => {
            Some(format!("{year}-{month:02}-{day:02}"))
        }
        PropertyValue::Time(h, m, s, cs) => {
            Some(format!("{h:02}:{m:02}:{s:02}.{cs:02}"))
        }
        _ => None,
    }
}
